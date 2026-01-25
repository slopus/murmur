/**
 * SQLite database storage for Murmur.
 *
 * Uses node:sqlite for synchronous, fast SQLite access.
 * Data is stored in ~/.murmur/murmur.db
 */

import { DatabaseSync } from 'node:sqlite'
import { mkdirSync, existsSync } from 'node:fs'
import { homedir } from 'node:os'
import { join, resolve } from 'node:path'
import { createId } from '@paralleldrive/cuid2'
import type { StoredAttachment, StoredContact, StoredMessage, Account, StoredHook, HookType } from './types.js'
import type { SerializedAgentState } from '../encryption/session/types.js'

/**
 * Get the Murmur data directory path.
 * Creates the directory if it doesn't exist.
 *
 * @param rootDir - If provided, use this directory instead of home
 */
export function getDataDir(rootDir?: string): string {
    const dir = rootDir ? resolve(rootDir) : join(homedir(), '.murmur')
    if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true })
    }
    return dir
}

/**
 * Get the database file path.
 *
 * @param rootDir - If provided, use this directory instead of home
 */
export function getDbPath(rootDir?: string): string {
    return join(getDataDir(rootDir), 'murmur.db')
}

/**
 * Database manager for Murmur storage.
 */
export class MurmurDatabase {
    private db: DatabaseSync

    constructor(dbPath?: string) {
        this.db = new DatabaseSync(dbPath ?? getDbPath())
        this.db.exec('PRAGMA foreign_keys = ON')
        this.db.exec('PRAGMA journal_mode = WAL')
        this.initSchema()
    }

    /**
     * Initialize database schema.
     */
    private initSchema(): void {
        this.db.exec(`
            -- Account table (only one row)
            CREATE TABLE IF NOT EXISTS account (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                identity_key TEXT NOT NULL,
                profile_public_key TEXT NOT NULL,
                profile_secret_key TEXT NOT NULL,
                encrypted_profile TEXT NOT NULL,
                first_name TEXT NOT NULL,
                last_name TEXT,
                created_at INTEGER NOT NULL
            );

            -- Agent state (serialized encryption state)
            CREATE TABLE IF NOT EXISTS agent_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                state_json TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );

            -- Contacts table
            CREATE TABLE IF NOT EXISTS contacts (
                identity_key TEXT PRIMARY KEY,
                profile_public_key TEXT NOT NULL,
                profile_secret_key TEXT,
                encrypted_profile TEXT NOT NULL,
                added_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            -- Messages table
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                is_outgoing INTEGER NOT NULL,
                text TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                read INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (conversation_id) REFERENCES contacts(identity_key)
            );

            -- Index for fetching messages by conversation
            CREATE INDEX IF NOT EXISTS idx_messages_conversation
            ON messages(conversation_id, created_at);

            -- Index for unread messages
            CREATE INDEX IF NOT EXISTS idx_messages_unread
            ON messages(conversation_id, read) WHERE read = 0;

            -- Migration tracker
            CREATE TABLE IF NOT EXISTS migrations (
                id TEXT PRIMARY KEY,
                applied_at INTEGER NOT NULL
            );
        `)

        this.runMigrations()
        this.ensureContactSchema()
    }

    /**
     * Run pending database migrations.
     */
    private runMigrations(): void {
        const appliedRows = this.db.prepare('SELECT id FROM migrations').all() as Array<{ id: string }>
        const applied = new Set(appliedRows.map(row => row.id))

        const migrations: Array<{ id: string; up: string }> = [
            {
                id: '202602010001_add_attachments',
                up: `
                    CREATE TABLE IF NOT EXISTS attachments (
                        message_id TEXT NOT NULL,
                        file_name TEXT NOT NULL,
                        hash TEXT NOT NULL,
                        iv TEXT NOT NULL,
                        key TEXT NOT NULL,
                        ciphertext TEXT NOT NULL,
                        created_at INTEGER NOT NULL,
                        FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE,
                        UNIQUE (message_id, file_name)
                    );

                    CREATE INDEX IF NOT EXISTS idx_attachments_message
                    ON attachments(message_id);
                `
            },
            {
                id: '202602150001_add_hooks',
                up: `
                    CREATE TABLE IF NOT EXISTS hooks (
                        id TEXT PRIMARY KEY,
                        type TEXT NOT NULL,
                        path TEXT NOT NULL,
                        args_json TEXT NOT NULL,
                        created_at INTEGER NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS idx_hooks_type
                    ON hooks(type);
                `
            }
        ]

        for (const migration of migrations) {
            if (applied.has(migration.id)) {
                continue
            }

            this.db.exec('BEGIN')
            try {
                this.db.exec(migration.up)
                this.db.prepare(
                    'INSERT INTO migrations (id, applied_at) VALUES (?, ?)'
                ).run(migration.id, Date.now())
                this.db.exec('COMMIT')
            } catch (error) {
                this.db.exec('ROLLBACK')
                throw error
            }
        }
    }

    /**
     * Ensure optional contact columns exist for older databases.
     */
    private ensureContactSchema(): void {
        const columns = this.db.prepare('PRAGMA table_info(contacts)').all() as Array<{ name: string }>
        const hasProfileSecretKey = columns.some(column => column.name === 'profile_secret_key')
        if (!hasProfileSecretKey) {
            this.db.exec('ALTER TABLE contacts ADD COLUMN profile_secret_key TEXT')
        }
    }

    /**
     * Check if an account exists.
     */
    hasAccount(): boolean {
        const row = this.db.prepare('SELECT 1 FROM account WHERE id = 1').get()
        return row !== undefined
    }

    /**
     * Get the account.
     */
    getAccount(): Account | null {
        const row = this.db.prepare(`
            SELECT identity_key, profile_public_key, profile_secret_key,
                   encrypted_profile, first_name, last_name, created_at
            FROM account WHERE id = 1
        `).get() as {
            identity_key: string
            profile_public_key: string
            profile_secret_key: string
            encrypted_profile: string
            first_name: string
            last_name: string | null
            created_at: number
        } | undefined

        if (!row) return null

        return {
            identityKey: row.identity_key,
            profilePublicKey: row.profile_public_key,
            profileSecretKey: row.profile_secret_key,
            encryptedProfile: row.encrypted_profile,
            firstName: row.first_name,
            lastName: row.last_name ?? undefined,
            createdAt: row.created_at
        }
    }

    /**
     * Save the account.
     */
    saveAccount(account: Account): void {
        this.db.prepare(`
            INSERT OR REPLACE INTO account
            (id, identity_key, profile_public_key, profile_secret_key,
             encrypted_profile, first_name, last_name, created_at)
            VALUES (1, ?, ?, ?, ?, ?, ?, ?)
        `).run(
            account.identityKey,
            account.profilePublicKey,
            account.profileSecretKey,
            account.encryptedProfile,
            account.firstName,
            account.lastName ?? null,
            account.createdAt
        )
    }

    /**
     * Get agent state.
     */
    getAgentState(): SerializedAgentState | null {
        const row = this.db.prepare(`
            SELECT state_json FROM agent_state WHERE id = 1
        `).get() as { state_json: string } | undefined

        if (!row) return null
        return JSON.parse(row.state_json)
    }

    /**
     * Save agent state.
     */
    saveAgentState(state: SerializedAgentState): void {
        this.db.prepare(`
            INSERT OR REPLACE INTO agent_state (id, state_json, updated_at)
            VALUES (1, ?, ?)
        `).run(JSON.stringify(state), Date.now())
    }

    /**
     * Clear all stored data.
     */
    clearAll(): void {
        this.db.exec('BEGIN')
        try {
            this.db.exec('DELETE FROM hooks')
            this.db.exec('DELETE FROM attachments')
            this.db.exec('DELETE FROM messages')
            this.db.exec('DELETE FROM contacts')
            this.db.exec('DELETE FROM agent_state')
            this.db.exec('DELETE FROM account')
            this.db.exec('COMMIT')
        } catch (error) {
            this.db.exec('ROLLBACK')
            throw error
        }
    }

    /**
     * Get registered hooks.
     */
    getHooks(type?: HookType): StoredHook[] {
        const query = `
            SELECT id, type, path, args_json, created_at
            FROM hooks
            ${type ? 'WHERE type = ?' : ''}
            ORDER BY created_at ASC
        `
        const rows = type
            ? (this.db.prepare(query).all(type) as Array<{
                id: string
                type: HookType
                path: string
                args_json: string
                created_at: number
            }>)
            : (this.db.prepare(query).all() as Array<{
                id: string
                type: HookType
                path: string
                args_json: string
                created_at: number
            }>)

        return rows.map(row => {
            let args: string[] = []
            try {
                const parsed = JSON.parse(row.args_json) as unknown
                if (Array.isArray(parsed)) {
                    args = parsed.filter((item): item is string => typeof item === 'string')
                }
            } catch {
                args = []
            }
            return {
                id: row.id,
                type: row.type,
                path: row.path,
                args,
                createdAt: row.created_at
            }
        })
    }

    /**
     * Add a new hook.
     */
    addHook(type: HookType, path: string, args: string[]): StoredHook {
        const id = createId()
        const createdAt = Date.now()
        const argsJson = JSON.stringify(args)
        this.db.prepare(`
            INSERT INTO hooks (id, type, path, args_json, created_at)
            VALUES (?, ?, ?, ?, ?)
        `).run(id, type, path, argsJson, createdAt)

        return {
            id,
            type,
            path,
            args,
            createdAt
        }
    }

    /**
     * Remove a hook by ID.
     */
    removeHook(id: string): number {
        const result = this.db.prepare(`
            DELETE FROM hooks WHERE id = ?
        `).run(id) as { changes?: number }
        return result.changes ?? 0
    }

    /**
     * Get all contacts.
     */
    getContacts(): StoredContact[] {
        const rows = this.db.prepare(`
            SELECT identity_key, profile_public_key, profile_secret_key, encrypted_profile,
                   added_at, updated_at
            FROM contacts ORDER BY added_at DESC
        `).all() as Array<{
            identity_key: string
            profile_public_key: string
            profile_secret_key: string | null
            encrypted_profile: string
            added_at: number
            updated_at: number
        }>

        return rows.map(row => ({
            identityKey: row.identity_key,
            profilePublicKey: row.profile_public_key,
            profileSecretKey: row.profile_secret_key ?? undefined,
            encryptedProfile: row.encrypted_profile,
            addedAt: row.added_at,
            updatedAt: row.updated_at
        }))
    }

    /**
     * Get a contact by identity key.
     */
    getContact(identityKey: string): StoredContact | null {
        const row = this.db.prepare(`
            SELECT identity_key, profile_public_key, profile_secret_key, encrypted_profile,
                   added_at, updated_at
            FROM contacts WHERE identity_key = ?
        `).get(identityKey) as {
            identity_key: string
            profile_public_key: string
            profile_secret_key: string | null
            encrypted_profile: string
            added_at: number
            updated_at: number
        } | undefined

        if (!row) return null

        return {
            identityKey: row.identity_key,
            profilePublicKey: row.profile_public_key,
            profileSecretKey: row.profile_secret_key ?? undefined,
            encryptedProfile: row.encrypted_profile,
            addedAt: row.added_at,
            updatedAt: row.updated_at
        }
    }

    /**
     * Save or update a contact.
     */
    saveContact(contact: StoredContact): void {
        this.db.prepare(`
            INSERT OR REPLACE INTO contacts
            (identity_key, profile_public_key, profile_secret_key, encrypted_profile, added_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
        `).run(
            contact.identityKey,
            contact.profilePublicKey,
            contact.profileSecretKey ?? null,
            contact.encryptedProfile,
            contact.addedAt,
            contact.updatedAt
        )
    }

    /**
     * Delete a contact and their messages.
     */
    deleteContact(identityKey: string): void {
        const deleteMessages = this.db.prepare(
            'DELETE FROM messages WHERE conversation_id = ?'
        )
        const deleteContact = this.db.prepare(
            'DELETE FROM contacts WHERE identity_key = ?'
        )

        this.db.exec('BEGIN')
        try {
            deleteMessages.run(identityKey)
            deleteContact.run(identityKey)
            this.db.exec('COMMIT')
        } catch (error) {
            this.db.exec('ROLLBACK')
            throw error
        }
    }

    /**
     * Get messages for a conversation.
     */
    getMessages(conversationId: string, limit: number = 100, offset: number = 0): StoredMessage[] {
        const rows = this.db.prepare(`
            SELECT id, conversation_id, is_outgoing, text, created_at, read
            FROM messages
            WHERE conversation_id = ?
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
        `).all(conversationId, limit, offset) as Array<{
            id: string
            conversation_id: string
            is_outgoing: number
            text: string
            created_at: number
            read: number
        }>

        const messageIds = rows.map(row => row.id)
        const attachments = this.getAttachmentsForMessages(messageIds)

        const messages = rows.map(row => {
            const message: StoredMessage = {
                id: row.id,
                conversationId: row.conversation_id,
                isOutgoing: row.is_outgoing === 1,
                text: row.text,
                createdAt: row.created_at,
                read: row.read === 1
            }
            const messageAttachments = attachments.get(row.id)
            if (messageAttachments && messageAttachments.length > 0) {
                message.attachments = messageAttachments
            }
            return message
        })

        return messages.reverse() // Return in chronological order
    }

    /**
     * Get unread incoming messages.
     */
    getUnreadMessages(conversationId?: string): StoredMessage[] {
        const rows = conversationId
            ? this.db.prepare(`
                SELECT id, conversation_id, is_outgoing, text, created_at, read
                FROM messages
                WHERE conversation_id = ? AND read = 0 AND is_outgoing = 0
                ORDER BY created_at ASC
            `).all(conversationId)
            : this.db.prepare(`
                SELECT id, conversation_id, is_outgoing, text, created_at, read
                FROM messages
                WHERE read = 0 AND is_outgoing = 0
                ORDER BY created_at ASC
            `).all()

        const typedRows = rows as Array<{
            id: string
            conversation_id: string
            is_outgoing: number
            text: string
            created_at: number
            read: number
        }>

        const messageIds = typedRows.map(row => row.id)
        const attachments = this.getAttachmentsForMessages(messageIds)

        return typedRows.map(row => {
            const message: StoredMessage = {
                id: row.id,
                conversationId: row.conversation_id,
                isOutgoing: row.is_outgoing === 1,
                text: row.text,
                createdAt: row.created_at,
                read: row.read === 1
            }
            const messageAttachments = attachments.get(row.id)
            if (messageAttachments && messageAttachments.length > 0) {
                message.attachments = messageAttachments
            }
            return message
        })
    }

    /**
     * Save a message.
     */
    saveMessage(message: StoredMessage): void {
        const attachments = message.attachments ?? []

        this.db.exec('BEGIN')
        try {
            this.db.prepare(`
                INSERT OR REPLACE INTO messages
                (id, conversation_id, is_outgoing, text, created_at, read)
                VALUES (?, ?, ?, ?, ?, ?)
            `).run(
                message.id,
                message.conversationId,
                message.isOutgoing ? 1 : 0,
                message.text,
                message.createdAt,
                message.read ? 1 : 0
            )

            this.db.prepare('DELETE FROM attachments WHERE message_id = ?').run(message.id)

            if (attachments.length > 0) {
                const insertAttachment = this.db.prepare(`
                    INSERT INTO attachments
                    (message_id, file_name, hash, iv, key, ciphertext, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                `)

                for (const attachment of attachments) {
                    insertAttachment.run(
                        message.id,
                        attachment.fileName,
                        attachment.hash,
                        attachment.iv,
                        attachment.key,
                        attachment.ciphertext,
                        message.createdAt
                    )
                }
            }

            this.db.exec('COMMIT')
        } catch (error) {
            this.db.exec('ROLLBACK')
            throw error
        }
    }

    /**
     * Check whether a message ID exists.
     */
    hasMessage(id: string): boolean {
        const row = this.db.prepare(`
            SELECT 1 FROM messages WHERE id = ? LIMIT 1
        `).get(id) as { 1: number } | undefined
        return row !== undefined
    }

    /**
     * Mark messages as read.
     */
    markMessagesRead(conversationId: string): void {
        this.db.prepare(`
            UPDATE messages SET read = 1
            WHERE conversation_id = ? AND read = 0
        `).run(conversationId)
    }

    /**
     * Mark messages as read by ID.
     */
    markMessagesReadById(ids: string[]): void {
        if (ids.length === 0) {
            return
        }
        const placeholders = ids.map(() => '?').join(', ')
        this.db.prepare(`
            UPDATE messages SET read = 1
            WHERE id IN (${placeholders})
        `).run(...ids)
    }

    /**
     * Get unread message count per conversation.
     */
    getUnreadCounts(): Map<string, number> {
        const rows = this.db.prepare(`
            SELECT conversation_id, COUNT(*) as count
            FROM messages
            WHERE read = 0 AND is_outgoing = 0
            GROUP BY conversation_id
        `).all() as Array<{ conversation_id: string; count: number }>

        const counts = new Map<string, number>()
        for (const row of rows) {
            counts.set(row.conversation_id, row.count)
        }
        return counts
    }

    /**
     * Get the last message for each conversation.
     */
    getLastMessages(): Map<string, StoredMessage> {
        const rows = this.db.prepare(`
            SELECT m.id, m.conversation_id, m.is_outgoing, m.text, m.created_at, m.read
            FROM messages m
            INNER JOIN (
                SELECT conversation_id, MAX(created_at) as max_created
                FROM messages
                GROUP BY conversation_id
            ) latest ON m.conversation_id = latest.conversation_id
                     AND m.created_at = latest.max_created
        `).all() as Array<{
            id: string
            conversation_id: string
            is_outgoing: number
            text: string
            created_at: number
            read: number
        }>

        const messageIds = rows.map(row => row.id)
        const attachments = this.getAttachmentsForMessages(messageIds)

        const messages = new Map<string, StoredMessage>()
        for (const row of rows) {
            const message: StoredMessage = {
                id: row.id,
                conversationId: row.conversation_id,
                isOutgoing: row.is_outgoing === 1,
                text: row.text,
                createdAt: row.created_at,
                read: row.read === 1
            }
            const messageAttachments = attachments.get(row.id)
            if (messageAttachments && messageAttachments.length > 0) {
                message.attachments = messageAttachments
            }
            messages.set(row.conversation_id, message)
        }
        return messages
    }

    /**
     * Get a specific attachment for a message.
     */
    getAttachment(messageId: string, fileName: string): StoredAttachment | null {
        const row = this.db.prepare(`
            SELECT file_name, hash, iv, key, ciphertext
            FROM attachments
            WHERE message_id = ? AND file_name = ?
            LIMIT 1
        `).get(messageId, fileName) as {
            file_name: string
            hash: string
            iv: string
            key: string
            ciphertext: string
        } | undefined

        if (!row) {
            return null
        }

        return {
            fileName: row.file_name,
            hash: row.hash,
            iv: row.iv,
            key: row.key,
            ciphertext: row.ciphertext
        }
    }

    /**
     * Fetch attachments for a set of message IDs.
     */
    private getAttachmentsForMessages(messageIds: string[]): Map<string, StoredAttachment[]> {
        const attachments = new Map<string, StoredAttachment[]>()
        if (messageIds.length === 0) {
            return attachments
        }

        const placeholders = messageIds.map(() => '?').join(', ')
        const rows = this.db.prepare(`
            SELECT message_id, file_name, hash, iv, key, ciphertext
            FROM attachments
            WHERE message_id IN (${placeholders})
            ORDER BY file_name ASC
        `).all(...messageIds) as Array<{
            message_id: string
            file_name: string
            hash: string
            iv: string
            key: string
            ciphertext: string
        }>

        for (const row of rows) {
            const entry: StoredAttachment = {
                fileName: row.file_name,
                hash: row.hash,
                iv: row.iv,
                key: row.key,
                ciphertext: row.ciphertext
            }
            const bucket = attachments.get(row.message_id)
            if (bucket) {
                bucket.push(entry)
            } else {
                attachments.set(row.message_id, [entry])
            }
        }

        return attachments
    }

    /**
     * Close the database connection.
     */
    close(): void {
        this.db.close()
    }
}
