/**
 * SQLite database storage for Murmur.
 *
 * Uses better-sqlite3 for synchronous, fast SQLite access.
 * Data is stored in ~/.murmur/murmur.db
 */

import Database from 'better-sqlite3'
import { mkdirSync, existsSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import type { StoredContact, StoredMessage, Account } from './types.js'
import type { SerializedAgentState } from '../encryption/session/types.js'

/**
 * Get the Murmur data directory path.
 * Creates the directory if it doesn't exist.
 */
export function getDataDir(): string {
    const dir = join(homedir(), '.murmur')
    if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true })
    }
    return dir
}

/**
 * Get the database file path.
 */
export function getDbPath(): string {
    return join(getDataDir(), 'murmur.db')
}

/**
 * Database manager for Murmur storage.
 */
export class MurmurDatabase {
    private db: Database.Database

    constructor(dbPath?: string) {
        this.db = new Database(dbPath ?? getDbPath())
        this.db.pragma('journal_mode = WAL')
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
        `)
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
     * Get all contacts.
     */
    getContacts(): StoredContact[] {
        const rows = this.db.prepare(`
            SELECT identity_key, profile_public_key, encrypted_profile,
                   added_at, updated_at
            FROM contacts ORDER BY added_at DESC
        `).all() as Array<{
            identity_key: string
            profile_public_key: string
            encrypted_profile: string
            added_at: number
            updated_at: number
        }>

        return rows.map(row => ({
            identityKey: row.identity_key,
            profilePublicKey: row.profile_public_key,
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
            SELECT identity_key, profile_public_key, encrypted_profile,
                   added_at, updated_at
            FROM contacts WHERE identity_key = ?
        `).get(identityKey) as {
            identity_key: string
            profile_public_key: string
            encrypted_profile: string
            added_at: number
            updated_at: number
        } | undefined

        if (!row) return null

        return {
            identityKey: row.identity_key,
            profilePublicKey: row.profile_public_key,
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
            (identity_key, profile_public_key, encrypted_profile, added_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
        `).run(
            contact.identityKey,
            contact.profilePublicKey,
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

        this.db.transaction(() => {
            deleteMessages.run(identityKey)
            deleteContact.run(identityKey)
        })()
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

        return rows.map(row => ({
            id: row.id,
            conversationId: row.conversation_id,
            isOutgoing: row.is_outgoing === 1,
            text: row.text,
            createdAt: row.created_at,
            read: row.read === 1
        })).reverse() // Return in chronological order
    }

    /**
     * Save a message.
     */
    saveMessage(message: StoredMessage): void {
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

        const messages = new Map<string, StoredMessage>()
        for (const row of rows) {
            messages.set(row.conversation_id, {
                id: row.id,
                conversationId: row.conversation_id,
                isOutgoing: row.is_outgoing === 1,
                text: row.text,
                createdAt: row.created_at,
                read: row.read === 1
            })
        }
        return messages
    }

    /**
     * Close the database connection.
     */
    close(): void {
        this.db.close()
    }
}
