import { bigintColumn, copyBytes, equalBytes, safeNumberColumn } from "../../utils/bytes.js";
import { isUuidV7, nextUuidV7 } from "../../utils/uuidV7.js";
import type { PostgresDatabase, PostgresQuery } from "../../storage/postgres/database.js";
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

const SCHEMA_LOCK = "7130618296230498781";

function text(value: unknown, name: string): string {
    if (typeof value !== "string") throw new Error(`Invalid ${name} in Postgres`);
    return value;
}

function nullableText(value: unknown, name: string): string | null {
    return value === null ? null : text(value, name);
}

function nullableBytes(value: unknown, name: string): Uint8Array | null {
    return value === null ? null : copyBytes(value, name);
}

function role(value: unknown): PrivateGroupRole {
    if (value !== "owner" && value !== "administrator" && value !== "member") {
        throw new Error("Invalid private-group member role in Postgres");
    }
    return value;
}

function operation(value: unknown): PrivateGroupChallengeOperation {
    if (value !== "create" && value !== "access") {
        throw new Error("Invalid private-group challenge operation in Postgres");
    }
    return value;
}

async function createSchema(database: PostgresDatabase): Promise<void> {
    await database.connection(async (connection) => {
        await connection.query("SELECT pg_advisory_lock($1::bigint)", [SCHEMA_LOCK]);
        try {
            const presence = await connection.query<{
                marker: unknown;
                global: unknown;
                records: unknown;
                members: unknown;
                challenges: unknown;
            }>(
                `SELECT
                    to_regclass('murmur_private_group_schema') AS marker,
                    to_regclass('murmur_private_group_global') AS global,
                    to_regclass('murmur_private_group_records') AS records,
                    to_regclass('murmur_private_group_members') AS members,
                    to_regclass('murmur_private_group_challenges') AS challenges`,
            );
            const row = presence.rows[0];
            if (row === undefined)
                throw new Error("Missing Postgres private-group schema inspection");
            const tables = [row.global, row.records, row.members, row.challenges];
            if (row.marker === null && tables.some((table) => table !== null)) {
                throw new Error("Incomplete Postgres private-group schema");
            }
            if (row.marker !== null) {
                if (tables.some((table) => table === null)) {
                    throw new Error("Incomplete Postgres private-group schema");
                }
                const version = await connection.query<{ version: unknown }>(
                    "SELECT version FROM murmur_private_group_schema WHERE singleton = 1",
                );
                if (bigintColumn(version.rows[0]?.version) !== 1n) {
                    throw new Error("Unsupported Postgres private-group schema version");
                }
                return;
            }
            await connection.transaction(async (transaction) => {
                for (const statement of [
                    `CREATE TABLE murmur_private_group_schema (
                        singleton bigint PRIMARY KEY CHECK (singleton = 1),
                        version bigint NOT NULL
                    )`,
                    `INSERT INTO murmur_private_group_schema (singleton, version)
                     VALUES (1, 1)`,
                    `CREATE TABLE murmur_private_group_global (
                        singleton bigint PRIMARY KEY CHECK (singleton = 1),
                        last_version uuid
                    )`,
                    `INSERT INTO murmur_private_group_global (singleton, last_version)
                     VALUES (1, NULL)`,
                    `CREATE TABLE murmur_private_group_records (
                        group_id bytea PRIMARY KEY CHECK (octet_length(group_id) = 32),
                        canonical_version uuid NOT NULL UNIQUE,
                        replaces_version uuid,
                        commit_event_id uuid,
                        public_parameters bytea NOT NULL,
                        revision bigint NOT NULL CHECK (revision >= 1),
                        previous_revision_hash bytea CHECK (
                            previous_revision_hash IS NULL OR
                            octet_length(previous_revision_hash) = 32
                        ),
                        revision_hash bytea NOT NULL CHECK (octet_length(revision_hash) = 32),
                        sealed_state bytea NOT NULL,
                        revision_authenticator bytea NOT NULL CHECK (
                            octet_length(revision_authenticator) = 32
                        ),
                        raw_record bytea NOT NULL,
                        encoded_bytes bigint NOT NULL CHECK (
                            encoded_bytes > 0 AND octet_length(raw_record) = encoded_bytes
                        )
                    )`,
                    `CREATE TABLE murmur_private_group_members (
                        group_id bytea NOT NULL REFERENCES murmur_private_group_records(group_id)
                            ON DELETE CASCADE,
                        entry bytea NOT NULL,
                        role text NOT NULL CHECK (role IN ('owner', 'administrator', 'member')),
                        PRIMARY KEY (group_id, entry)
                    )`,
                    `CREATE INDEX murmur_private_group_member_role
                     ON murmur_private_group_members(group_id, role)`,
                    `CREATE TABLE murmur_private_group_challenges (
                        replay_nonce bytea PRIMARY KEY CHECK (octet_length(replay_nonce) = 32),
                        group_id bytea NOT NULL CHECK (octet_length(group_id) = 32),
                        entry bytea NOT NULL,
                        role text NOT NULL CHECK (role IN ('owner', 'administrator', 'member')),
                        operation text NOT NULL CHECK (operation IN ('create', 'access')),
                        context bytea NOT NULL,
                        expires_at bigint NOT NULL
                    )`,
                    `CREATE INDEX murmur_private_group_challenge_expiry
                     ON murmur_private_group_challenges(expires_at)`,
                ]) {
                    await transaction.query(statement);
                }
            });
        } finally {
            await connection.query("SELECT pg_advisory_unlock($1::bigint)", [SCHEMA_LOCK]);
        }
    });
}

/** Postgres/PGlite storage for canonical opaque private-group state. */
export class PostgresPrivateGroupStateStore implements PrivateGroupStateStore {
    readonly #database: PostgresDatabase;
    #closed = false;

    private constructor(database: PostgresDatabase) {
        this.#database = database;
    }

    /** Create or validate the single clean beta schema and return its store. */
    static async create(database: PostgresDatabase): Promise<PostgresPrivateGroupStateStore> {
        await createSchema(database);
        return new PostgresPrivateGroupStateStore(database);
    }

    async create(
        record: PrivateGroupStateRecord,
        revisionHash: Uint8Array,
        rawRecord: Uint8Array,
        limits: PrivateGroupStateLimits,
        now: number,
    ): Promise<StoredPrivateGroupStateRecord> {
        this.#assertOpen();
        return this.#database.transaction(async (transaction) => {
            const global = await transaction.query<{ last_version: unknown }>(
                `SELECT last_version FROM murmur_private_group_global
                 WHERE singleton = 1 FOR UPDATE`,
            );
            const lastVersion = nullableText(
                global.rows[0]?.last_version,
                "last private-group version",
            );
            const existing = await this.#read(transaction, record.opaqueGroupId);
            if (existing !== undefined) {
                if (!equalBytes(existing.revisionHash, revisionHash)) {
                    throw new Error("Private group already exists with different state");
                }
                return existing;
            }
            const usage = await transaction.query<{ group_count: unknown }>(
                "SELECT COUNT(*) AS group_count FROM murmur_private_group_records",
            );
            if (bigintColumn(usage.rows[0]?.group_count) >= BigInt(limits.maximumGroups)) {
                throw new Error("Private-group service group quota exceeded");
            }
            const canonicalVersion = nextUuidV7(now, lastVersion);
            await transaction.query(
                `INSERT INTO murmur_private_group_records
                    (group_id, canonical_version, replaces_version, commit_event_id,
                     public_parameters, revision, previous_revision_hash, revision_hash,
                     sealed_state, revision_authenticator, raw_record, encoded_bytes)
                 VALUES ($1, $2, NULL, NULL, $3, $4, $5, $6, $7, $8, $9, $10)`,
                [
                    record.opaqueGroupId,
                    canonicalVersion,
                    record.publicParameters,
                    record.revision.toString(),
                    record.previousRevisionHash,
                    revisionHash,
                    record.sealedState,
                    record.revisionAuthenticator,
                    rawRecord,
                    rawRecord.length.toString(),
                ],
            );
            await this.#insertMembers(transaction, record.opaqueGroupId, record.members);
            await transaction.query(
                `UPDATE murmur_private_group_global SET last_version = $1
                 WHERE singleton = 1`,
                [canonicalVersion],
            );
            const stored = await this.#read(transaction, record.opaqueGroupId);
            if (stored === undefined)
                throw new Error("Created private-group record was not persisted");
            return stored;
        });
    }

    async replace(
        replacesVersion: string,
        expectedRevisionHash: Uint8Array,
        record: PrivateGroupStateRecord,
        revisionHash: Uint8Array,
        rawRecord: Uint8Array,
        _limits: PrivateGroupStateLimits,
        now: number,
    ): Promise<StoredPrivateGroupStateRecord> {
        this.#assertOpen();
        return this.#database.transaction(async (transaction) => {
            await transaction.query(
                `SELECT canonical_version FROM murmur_private_group_records
                 WHERE group_id = $1 FOR UPDATE`,
                [record.opaqueGroupId],
            );
            const current = await this.#read(transaction, record.opaqueGroupId);
            if (current === undefined) throw new Error("Unknown private group");
            if (
                current.replacesVersion === replacesVersion &&
                equalBytes(current.revisionHash, revisionHash)
            ) {
                return current;
            }
            if (
                current.canonicalVersion !== replacesVersion ||
                current.record.revision + 1 !== record.revision ||
                !equalBytes(current.revisionHash, expectedRevisionHash)
            ) {
                throw new Error("Private-group canonical version conflict");
            }
            const global = await transaction.query<{ last_version: unknown }>(
                `SELECT last_version FROM murmur_private_group_global
                 WHERE singleton = 1 FOR UPDATE`,
            );
            const canonicalVersion = nextUuidV7(
                now,
                nullableText(global.rows[0]?.last_version, "last private-group version"),
            );
            const updated = await transaction.query<{ group_id: unknown }>(
                `UPDATE murmur_private_group_records
                 SET canonical_version = $1, replaces_version = $2, commit_event_id = NULL,
                     public_parameters = $3, revision = $4, previous_revision_hash = $5,
                     revision_hash = $6, sealed_state = $7, revision_authenticator = $8,
                     raw_record = $9, encoded_bytes = $10
                 WHERE group_id = $11 AND canonical_version = $2 AND revision_hash = $12
                 RETURNING group_id`,
                [
                    canonicalVersion,
                    replacesVersion,
                    record.publicParameters,
                    record.revision.toString(),
                    record.previousRevisionHash,
                    revisionHash,
                    record.sealedState,
                    record.revisionAuthenticator,
                    rawRecord,
                    rawRecord.length.toString(),
                    record.opaqueGroupId,
                    expectedRevisionHash,
                ],
            );
            if (updated.rows.length !== 1) {
                throw new Error("Private-group canonical version conflict");
            }
            await transaction.query(
                "DELETE FROM murmur_private_group_members WHERE group_id = $1",
                [record.opaqueGroupId],
            );
            await this.#insertMembers(transaction, record.opaqueGroupId, record.members);
            await transaction.query(
                `UPDATE murmur_private_group_global SET last_version = $1
                 WHERE singleton = 1`,
                [canonicalVersion],
            );
            const stored = await this.#read(transaction, record.opaqueGroupId);
            if (stored === undefined)
                throw new Error("Replaced private-group record was not persisted");
            return stored;
        });
    }

    async read(opaqueGroupId: Uint8Array): Promise<StoredPrivateGroupStateRecord | undefined> {
        this.#assertOpen();
        return this.#database.transaction(
            async (transaction) => this.#read(transaction, opaqueGroupId),
            "repeatable read",
        );
    }

    async hasMember(
        opaqueGroupId: Uint8Array,
        entry: Uint8Array,
        expectedRole: PrivateGroupRole,
    ): Promise<boolean> {
        this.#assertOpen();
        const result = await this.#database.query<{ present: unknown }>(
            `SELECT 1 AS present FROM murmur_private_group_members
             WHERE group_id = $1 AND entry = $2 AND role = $3`,
            [opaqueGroupId, entry, expectedRole],
        );
        return result.rows[0] !== undefined;
    }

    async storeChallenge(
        challenge: PrivateGroupPresentationChallenge,
        maximumPendingChallenges: number,
        now: number,
    ): Promise<void> {
        this.#assertOpen();
        await this.#database.transaction(async (transaction) => {
            await transaction.query(
                "DELETE FROM murmur_private_group_challenges WHERE expires_at <= $1",
                [now.toString()],
            );
            const count = await transaction.query<{ challenge_count: unknown }>(
                "SELECT COUNT(*) AS challenge_count FROM murmur_private_group_challenges",
            );
            if (bigintColumn(count.rows[0]?.challenge_count) >= BigInt(maximumPendingChallenges)) {
                throw new Error("Private-group presentation challenge quota exceeded");
            }
            await transaction.query(
                `INSERT INTO murmur_private_group_challenges
                    (replay_nonce, group_id, entry, role, operation, context, expires_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
                [
                    challenge.replayNonce,
                    challenge.opaqueGroupId,
                    challenge.entry,
                    challenge.role,
                    challenge.operation,
                    challenge.context,
                    challenge.expiresAt.toString(),
                ],
            );
        });
    }

    async consumeChallenge(
        replayNonce: Uint8Array,
        now: number,
    ): Promise<PrivateGroupPresentationChallenge | undefined> {
        this.#assertOpen();
        return this.#database.transaction(async (transaction) => {
            await transaction.query(
                "DELETE FROM murmur_private_group_challenges WHERE expires_at <= $1",
                [now.toString()],
            );
            const consumed = await transaction.query<{
                group_id: unknown;
                entry: unknown;
                role: unknown;
                operation: unknown;
                context: unknown;
                expires_at: unknown;
            }>(
                `DELETE FROM murmur_private_group_challenges WHERE replay_nonce = $1
                 RETURNING group_id, entry, role, operation, context, expires_at`,
                [replayNonce],
            );
            const row = consumed.rows[0];
            return row === undefined
                ? undefined
                : {
                      opaqueGroupId: copyBytes(row.group_id, "challenge group ID"),
                      entry: copyBytes(row.entry, "challenge member entry"),
                      role: role(row.role),
                      operation: operation(row.operation),
                      replayNonce: replayNonce.slice(),
                      context: copyBytes(row.context, "challenge context"),
                      expiresAt: safeNumberColumn(row.expires_at),
                  };
        });
    }

    /** Release this facade; the caller retains ownership of the shared database. */
    close(): void {
        this.#closed = true;
    }

    async #read(
        query: PostgresQuery,
        opaqueGroupId: Uint8Array,
    ): Promise<StoredPrivateGroupStateRecord | undefined> {
        const result = await query.query<{
            canonical_version: unknown;
            replaces_version: unknown;
            commit_event_id: unknown;
            public_parameters: unknown;
            revision: unknown;
            previous_revision_hash: unknown;
            revision_hash: unknown;
            sealed_state: unknown;
            revision_authenticator: unknown;
        }>(
            `SELECT canonical_version, replaces_version, commit_event_id, public_parameters,
                    revision, previous_revision_hash, revision_hash, sealed_state,
                    revision_authenticator
             FROM murmur_private_group_records WHERE group_id = $1`,
            [opaqueGroupId],
        );
        const stored = result.rows[0];
        if (stored === undefined) return undefined;
        const canonicalVersion = text(stored.canonical_version, "private-group canonical version");
        const replacesVersion = nullableText(
            stored.replaces_version,
            "replaced private-group version",
        );
        const commitEventId = nullableText(stored.commit_event_id, "private-group Commit event ID");
        if (
            !isUuidV7(canonicalVersion) ||
            (replacesVersion !== null && !isUuidV7(replacesVersion)) ||
            (commitEventId !== null && !isUuidV7(commitEventId))
        ) {
            throw new Error("Invalid private-group canonical metadata in Postgres");
        }
        const memberResult = await query.query<{ entry: unknown; role: unknown }>(
            `SELECT entry, role FROM murmur_private_group_members
             WHERE group_id = $1 ORDER BY entry`,
            [opaqueGroupId],
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
                members: memberResult.rows.map(
                    (member): PrivateGroupMemberEntry => ({
                        entry: copyBytes(member.entry, "private-group member entry"),
                        role: role(member.role),
                    }),
                ),
                sealedState: copyBytes(stored.sealed_state, "private-group sealed state"),
                revisionAuthenticator: copyBytes(
                    stored.revision_authenticator,
                    "private-group revision authenticator",
                ),
            },
            revisionHash: copyBytes(stored.revision_hash, "private-group revision hash"),
            canonicalVersion,
            replacesVersion,
            commitEventId,
        };
    }

    async #insertMembers(
        query: PostgresQuery,
        opaqueGroupId: Uint8Array,
        members: readonly PrivateGroupMemberEntry[],
    ): Promise<void> {
        for (const member of members) {
            await query.query(
                `INSERT INTO murmur_private_group_members (group_id, entry, role)
                 VALUES ($1, $2, $3)`,
                [opaqueGroupId, member.entry, member.role],
            );
        }
    }

    #assertOpen(): void {
        if (this.#closed) throw new Error("Postgres private-group store is closed");
    }
}
