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
import type {
    StoredAttachment,
    StoredContact,
    StoredFeed,
    StoredFeedItem,
    StoredFeedKey,
    StoredFeedMember,
    StoredMessage,
    Account,
    StoredHook,
    HookType
} from './types.js'
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
                updated_at INTEGER NOT NULL,
                blocked INTEGER NOT NULL DEFAULT 0
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
            },
            {
                id: '202602150002_message_hooks',
                up: `
                    UPDATE hooks SET type = 'message' WHERE type = 'verify-message';
                `
            },
            {
                id: '202602160001_add_settings',
                up: `
                    CREATE TABLE IF NOT EXISTS settings (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    );
                `
            },
            {
                id: '202604070001_add_feeds',
                up: `
                    CREATE TABLE IF NOT EXISTS feeds (
                        feed_id TEXT PRIMARY KEY,
                        owner_id TEXT NOT NULL,
                        encrypted_metadata TEXT,
                        current_epoch INTEGER NOT NULL,
                        created_at INTEGER NOT NULL,
                        updated_at INTEGER NOT NULL,
                        owned INTEGER NOT NULL DEFAULT 0
                    );

                    CREATE TABLE IF NOT EXISTS feed_members (
                        feed_id TEXT NOT NULL,
                        member_id TEXT NOT NULL,
                        added_at INTEGER NOT NULL,
                        PRIMARY KEY (feed_id, member_id),
                        FOREIGN KEY (feed_id) REFERENCES feeds(feed_id) ON DELETE CASCADE
                    );

                    CREATE TABLE IF NOT EXISTS feed_keys (
                        feed_id TEXT NOT NULL,
                        epoch INTEGER NOT NULL,
                        key TEXT NOT NULL,
                        added_at INTEGER NOT NULL,
                        PRIMARY KEY (feed_id, epoch),
                        FOREIGN KEY (feed_id) REFERENCES feeds(feed_id) ON DELETE CASCADE
                    );

                    CREATE TABLE IF NOT EXISTS feed_items (
                        item_id TEXT PRIMARY KEY,
                        feed_id TEXT NOT NULL,
                        author_id TEXT NOT NULL,
                        epoch INTEGER NOT NULL,
                        text TEXT NOT NULL,
                        attachments_json TEXT,
                        signature TEXT NOT NULL,
                        created_at INTEGER NOT NULL,
                        FOREIGN KEY (feed_id) REFERENCES feeds(feed_id) ON DELETE CASCADE
                    );

                    CREATE INDEX IF NOT EXISTS idx_feed_items_created_at
                    ON feed_items(created_at DESC, item_id DESC);

                    CREATE INDEX IF NOT EXISTS idx_feed_items_feed
                    ON feed_items(feed_id, created_at DESC, item_id DESC);
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
        const hasBlocked = columns.some(column => column.name === 'blocked')
        if (!hasBlocked) {
            this.db.exec('ALTER TABLE contacts ADD COLUMN blocked INTEGER NOT NULL DEFAULT 0')
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
            this.db.exec('DELETE FROM settings')
            this.db.exec('DELETE FROM hooks')
            this.db.exec('DELETE FROM feed_items')
            this.db.exec('DELETE FROM feed_keys')
            this.db.exec('DELETE FROM feed_members')
            this.db.exec('DELETE FROM feeds')
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
     * Get a setting value by key.
     */
    getSetting(key: string): string | null {
        const row = this.db.prepare('SELECT value FROM settings WHERE key = ?').get(key) as { value: string } | undefined
        return row?.value ?? null
    }

    /**
     * Set a setting value by key.
     */
    setSetting(key: string, value: string): void {
        this.db.prepare(`
            INSERT OR REPLACE INTO settings (key, value)
            VALUES (?, ?)
        `).run(key, value)
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
                   added_at, updated_at, blocked
            FROM contacts ORDER BY added_at DESC
        `).all() as Array<{
            identity_key: string
            profile_public_key: string
            profile_secret_key: string | null
            encrypted_profile: string
            added_at: number
            updated_at: number
            blocked: number
        }>

        return rows.map(row => ({
            identityKey: row.identity_key,
            profilePublicKey: row.profile_public_key,
            profileSecretKey: row.profile_secret_key ?? undefined,
            encryptedProfile: row.encrypted_profile,
            addedAt: row.added_at,
            updatedAt: row.updated_at,
            blocked: row.blocked === 1
        }))
    }

    /**
     * Get a contact by identity key.
     */
    getContact(identityKey: string): StoredContact | null {
        const row = this.db.prepare(`
            SELECT identity_key, profile_public_key, profile_secret_key, encrypted_profile,
                   added_at, updated_at, blocked
            FROM contacts WHERE identity_key = ?
        `).get(identityKey) as {
            identity_key: string
            profile_public_key: string
            profile_secret_key: string | null
            encrypted_profile: string
            added_at: number
            updated_at: number
            blocked: number
        } | undefined

        if (!row) return null

        return {
            identityKey: row.identity_key,
            profilePublicKey: row.profile_public_key,
            profileSecretKey: row.profile_secret_key ?? undefined,
            encryptedProfile: row.encrypted_profile,
            addedAt: row.added_at,
            updatedAt: row.updated_at,
            blocked: row.blocked === 1
        }
    }

    /**
     * Save or update a contact.
     */
    saveContact(contact: StoredContact): void {
        this.db.prepare(`
            INSERT OR REPLACE INTO contacts
            (identity_key, profile_public_key, profile_secret_key, encrypted_profile, added_at, updated_at, blocked)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `).run(
            contact.identityKey,
            contact.profilePublicKey,
            contact.profileSecretKey ?? null,
            contact.encryptedProfile,
            contact.addedAt,
            contact.updatedAt,
            contact.blocked ? 1 : 0
        )
    }

    /**
     * Get a contact by profile public key.
     */
    getContactByProfilePublicKey(profilePublicKey: string): StoredContact | null {
        const row = this.db.prepare(`
            SELECT identity_key, profile_public_key, profile_secret_key, encrypted_profile,
                   added_at, updated_at, blocked
            FROM contacts WHERE profile_public_key = ?
        `).get(profilePublicKey) as {
            identity_key: string
            profile_public_key: string
            profile_secret_key: string | null
            encrypted_profile: string
            added_at: number
            updated_at: number
            blocked: number
        } | undefined

        if (!row) return null

        return {
            identityKey: row.identity_key,
            profilePublicKey: row.profile_public_key,
            profileSecretKey: row.profile_secret_key ?? undefined,
            encryptedProfile: row.encrypted_profile,
            addedAt: row.added_at,
            updatedAt: row.updated_at,
            blocked: row.blocked === 1
        }
    }

    /**
     * Update block status for a contact.
     */
    setContactBlocked(identityKey: string, blocked: boolean): number {
        const result = this.db.prepare(`
            UPDATE contacts SET blocked = ?, updated_at = ? WHERE identity_key = ?
        `).run(blocked ? 1 : 0, Date.now(), identityKey) as { changes?: number }
        return result.changes ?? 0
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

    getFeeds(owned?: boolean): StoredFeed[] {
        const rows = owned === undefined
            ? this.db.prepare(`
                SELECT feed_id, owner_id, encrypted_metadata, current_epoch, created_at, updated_at, owned
                FROM feeds
                ORDER BY updated_at DESC
            `).all()
            : this.db.prepare(`
                SELECT feed_id, owner_id, encrypted_metadata, current_epoch, created_at, updated_at, owned
                FROM feeds
                WHERE owned = ?
                ORDER BY updated_at DESC
            `).all(owned ? 1 : 0)

        return (rows as Array<{
            feed_id: string
            owner_id: string
            encrypted_metadata: string | null
            current_epoch: number
            created_at: number
            updated_at: number
            owned: number
        }>).map(row => ({
            feedId: row.feed_id,
            ownerId: row.owner_id,
            encryptedMetadata: row.encrypted_metadata ?? undefined,
            currentEpoch: row.current_epoch,
            createdAt: row.created_at,
            updatedAt: row.updated_at,
            owned: row.owned === 1
        }))
    }

    getFeed(feedId: string): StoredFeed | null {
        const row = this.db.prepare(`
            SELECT feed_id, owner_id, encrypted_metadata, current_epoch, created_at, updated_at, owned
            FROM feeds
            WHERE feed_id = ?
            LIMIT 1
        `).get(feedId) as {
            feed_id: string
            owner_id: string
            encrypted_metadata: string | null
            current_epoch: number
            created_at: number
            updated_at: number
            owned: number
        } | undefined

        if (!row) {
            return null
        }

        return {
            feedId: row.feed_id,
            ownerId: row.owner_id,
            encryptedMetadata: row.encrypted_metadata ?? undefined,
            currentEpoch: row.current_epoch,
            createdAt: row.created_at,
            updatedAt: row.updated_at,
            owned: row.owned === 1
        }
    }

    saveFeed(feed: StoredFeed): void {
        this.db.prepare(`
            INSERT OR REPLACE INTO feeds
            (feed_id, owner_id, encrypted_metadata, current_epoch, created_at, updated_at, owned)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `).run(
            feed.feedId,
            feed.ownerId,
            feed.encryptedMetadata ?? null,
            feed.currentEpoch,
            feed.createdAt,
            feed.updatedAt,
            feed.owned ? 1 : 0
        )
    }

    deleteFeed(feedId: string): void {
        this.db.prepare('DELETE FROM feeds WHERE feed_id = ?').run(feedId)
    }

    getFeedMembers(feedId: string): StoredFeedMember[] {
        const rows = this.db.prepare(`
            SELECT feed_id, member_id, added_at
            FROM feed_members
            WHERE feed_id = ?
            ORDER BY member_id ASC
        `).all(feedId) as Array<{
            feed_id: string
            member_id: string
            added_at: number
        }>

        return rows.map(row => ({
            feedId: row.feed_id,
            memberId: row.member_id,
            addedAt: row.added_at
        }))
    }

    replaceFeedMembers(feedId: string, memberIds: string[]): void {
        const now = Date.now()
        this.db.exec('BEGIN')
        try {
            this.db.prepare('DELETE FROM feed_members WHERE feed_id = ?').run(feedId)
            const insert = this.db.prepare(`
                INSERT INTO feed_members (feed_id, member_id, added_at)
                VALUES (?, ?, ?)
            `)
            for (const memberId of memberIds) {
                insert.run(feedId, memberId, now)
            }
            this.db.exec('COMMIT')
        } catch (error) {
            this.db.exec('ROLLBACK')
            throw error
        }
    }

    saveFeedKey(feedKey: StoredFeedKey): void {
        this.db.prepare(`
            INSERT OR REPLACE INTO feed_keys (feed_id, epoch, key, added_at)
            VALUES (?, ?, ?, ?)
        `).run(feedKey.feedId, feedKey.epoch, feedKey.key, feedKey.addedAt)
    }

    getFeedKey(feedId: string, epoch: number): StoredFeedKey | null {
        const row = this.db.prepare(`
            SELECT feed_id, epoch, key, added_at
            FROM feed_keys
            WHERE feed_id = ? AND epoch = ?
            LIMIT 1
        `).get(feedId, epoch) as {
            feed_id: string
            epoch: number
            key: string
            added_at: number
        } | undefined

        if (!row) {
            return null
        }

        return {
            feedId: row.feed_id,
            epoch: row.epoch,
            key: row.key,
            addedAt: row.added_at
        }
    }

    getFeedKeys(feedId: string): StoredFeedKey[] {
        const rows = this.db.prepare(`
            SELECT feed_id, epoch, key, added_at
            FROM feed_keys
            WHERE feed_id = ?
            ORDER BY epoch ASC
        `).all(feedId) as Array<{
            feed_id: string
            epoch: number
            key: string
            added_at: number
        }>

        return rows.map(row => ({
            feedId: row.feed_id,
            epoch: row.epoch,
            key: row.key,
            addedAt: row.added_at
        }))
    }

    saveFeedItem(item: StoredFeedItem): void {
        this.db.prepare(`
            INSERT OR REPLACE INTO feed_items
            (item_id, feed_id, author_id, epoch, text, attachments_json, signature, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
            item.itemId,
            item.feedId,
            item.authorId,
            item.epoch,
            item.text,
            JSON.stringify(item.attachments ?? []),
            item.signature,
            item.createdAt
        )
    }

    getTimelineFeedItems(limit: number = 50): StoredFeedItem[] {
        const rows = this.db.prepare(`
            SELECT item_id, feed_id, author_id, epoch, text, attachments_json, signature, created_at
            FROM feed_items
            ORDER BY created_at DESC, item_id DESC
            LIMIT ?
        `).all(limit) as Array<{
            item_id: string
            feed_id: string
            author_id: string
            epoch: number
            text: string
            attachments_json: string | null
            signature: string
            created_at: number
        }>

        return rows.map(row => ({
            itemId: row.item_id,
            feedId: row.feed_id,
            authorId: row.author_id,
            epoch: row.epoch,
            text: row.text,
            attachments: this.parseStoredAttachments(row.attachments_json),
            signature: row.signature,
            createdAt: row.created_at
        }))
    }

    getFeedItems(feedId: string, limit: number = 50): StoredFeedItem[] {
        const rows = this.db.prepare(`
            SELECT item_id, feed_id, author_id, epoch, text, attachments_json, signature, created_at
            FROM feed_items
            WHERE feed_id = ?
            ORDER BY created_at DESC, item_id DESC
            LIMIT ?
        `).all(feedId, limit) as Array<{
            item_id: string
            feed_id: string
            author_id: string
            epoch: number
            text: string
            attachments_json: string | null
            signature: string
            created_at: number
        }>

        return rows.map(row => ({
            itemId: row.item_id,
            feedId: row.feed_id,
            authorId: row.author_id,
            epoch: row.epoch,
            text: row.text,
            attachments: this.parseStoredAttachments(row.attachments_json),
            signature: row.signature,
            createdAt: row.created_at
        }))
    }

    private parseStoredAttachments(value: string | null): StoredAttachment[] | undefined {
        if (!value) {
            return undefined
        }

        try {
            const parsed = JSON.parse(value) as unknown
            if (!Array.isArray(parsed)) {
                return undefined
            }
            const attachments = parsed.filter((entry): entry is StoredAttachment => (
                typeof entry === 'object'
                && entry !== null
                && typeof (entry as StoredAttachment).fileName === 'string'
                && typeof (entry as StoredAttachment).hash === 'string'
                && typeof (entry as StoredAttachment).iv === 'string'
                && typeof (entry as StoredAttachment).key === 'string'
                && typeof (entry as StoredAttachment).ciphertext === 'string'
            ))
            return attachments.length > 0 ? attachments : undefined
        } catch {
            return undefined
        }
    }

    /**
     * Close the database connection.
     */
    close(): void {
        this.db.close()
    }
}
