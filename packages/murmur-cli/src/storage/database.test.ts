/**
 * Tests for SQLite database storage.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { MurmurDatabase } from './database.js'
import type { Account, StoredContact, StoredMessage } from './types.js'
import type { SerializedAgentState } from '../encryption/session/types.js'

describe('MurmurDatabase', () => {
    let db: MurmurDatabase
    let tempDir: string

    beforeEach(() => {
        tempDir = mkdtempSync(join(tmpdir(), 'murmur-test-'))
        db = new MurmurDatabase(join(tempDir, 'test.db'))
    })

    afterEach(() => {
        db.close()
        rmSync(tempDir, { recursive: true, force: true })
    })

    describe('Account', () => {
        it('should report no account initially', () => {
            expect(db.hasAccount()).toBe(false)
            expect(db.getAccount()).toBeNull()
        })

        it('should save and retrieve account', () => {
            const account: Account = {
                identityKey: 'test-identity-key',
                profilePublicKey: 'test-profile-public-key',
                profileSecretKey: 'test-profile-secret-key',
                encryptedProfile: 'encrypted-profile-data',
                firstName: 'Alice',
                lastName: 'Smith',
                createdAt: Date.now()
            }

            db.saveAccount(account)

            expect(db.hasAccount()).toBe(true)
            const retrieved = db.getAccount()
            expect(retrieved).toEqual(account)
        })

        it('should save account without lastName', () => {
            const account: Account = {
                identityKey: 'test-identity-key',
                profilePublicKey: 'test-profile-public-key',
                profileSecretKey: 'test-profile-secret-key',
                encryptedProfile: 'encrypted-profile-data',
                firstName: 'Bob',
                createdAt: Date.now()
            }

            db.saveAccount(account)

            const retrieved = db.getAccount()
            expect(retrieved?.firstName).toBe('Bob')
            expect(retrieved?.lastName).toBeUndefined()
        })

        it('should update existing account', () => {
            const account1: Account = {
                identityKey: 'key1',
                profilePublicKey: 'ppk1',
                profileSecretKey: 'psk1',
                encryptedProfile: 'ep1',
                firstName: 'Alice',
                createdAt: 1000
            }

            const account2: Account = {
                identityKey: 'key2',
                profilePublicKey: 'ppk2',
                profileSecretKey: 'psk2',
                encryptedProfile: 'ep2',
                firstName: 'Alice Updated',
                lastName: 'Smith',
                createdAt: 2000
            }

            db.saveAccount(account1)
            db.saveAccount(account2)

            const retrieved = db.getAccount()
            expect(retrieved?.identityKey).toBe('key2')
            expect(retrieved?.firstName).toBe('Alice Updated')
        })

        it('should clear all data', () => {
            const account: Account = {
                identityKey: 'key1',
                profilePublicKey: 'ppk1',
                profileSecretKey: 'psk1',
                encryptedProfile: 'ep1',
                firstName: 'Alice',
                createdAt: 1000
            }
            const state: SerializedAgentState = {
                keyStore: {
                    identityPrivateKey: 'id-private',
                    identityPublicKey: 'id-public',
                    identityDHPrivateKey: 'idh-private',
                    identityDHPublicKey: 'idh-public',
                    signedPreKey: {
                        id: 1,
                        privateKey: 'spk-private',
                        publicKey: 'spk-public',
                        signature: 'spk-signature',
                        createdAt: 1234
                    },
                    oneTimePreKeys: [],
                    nextPreKeyId: 2
                },
                sessions: []
            }
            const contact: StoredContact = {
                identityKey: 'contact-id',
                profilePublicKey: 'contact-ppk',
                profileSecretKey: 'contact-psk',
                encryptedProfile: 'contact-ep',
                addedAt: 1000,
                updatedAt: 1000
            }
            const message: StoredMessage = {
                id: 'msg-1',
                conversationId: 'contact-id',
                isOutgoing: true,
                text: 'Hello',
                createdAt: 1000,
                read: true
            }

            db.saveAccount(account)
            db.saveAgentState(state)
            db.saveContact(contact)
            db.saveMessage(message)

            db.clearAll()

            expect(db.getAccount()).toBeNull()
            expect(db.getAgentState()).toBeNull()
            expect(db.getContacts()).toEqual([])
            expect(db.getMessages('contact-id')).toEqual([])
        })
    })

    describe('Agent State', () => {
        it('should return null for no state', () => {
            expect(db.getAgentState()).toBeNull()
        })

        it('should save and retrieve agent state', () => {
            const state: SerializedAgentState = {
                keyStore: {
                    identityPrivateKey: 'id-private',
                    identityPublicKey: 'id-public',
                    identityDHPrivateKey: 'idh-private',
                    identityDHPublicKey: 'idh-public',
                    signedPreKey: {
                        id: 1,
                        privateKey: 'spk-private',
                        publicKey: 'spk-public',
                        signature: 'spk-signature',
                        createdAt: 1234
                    },
                    oneTimePreKeys: [],
                    nextPreKeyId: 2
                },
                sessions: []
            }

            db.saveAgentState(state)

            const retrieved = db.getAgentState()
            expect(retrieved).toEqual(state)
        })
    })

    describe('Contacts', () => {
        it('should return empty array initially', () => {
            expect(db.getContacts()).toEqual([])
        })

        it('should save and retrieve contact', () => {
            const contact: StoredContact = {
                identityKey: 'contact-id-key',
                profilePublicKey: 'contact-profile-key',
                profileSecretKey: 'contact-profile-secret',
                encryptedProfile: 'encrypted-data',
                addedAt: 1000,
                updatedAt: 2000
            }

            db.saveContact(contact)

            const contacts = db.getContacts()
            expect(contacts).toHaveLength(1)
            expect(contacts[0]).toEqual(contact)
        })

        it('should get contact by identity key', () => {
            const contact: StoredContact = {
                identityKey: 'specific-key',
                profilePublicKey: 'ppk',
                profileSecretKey: 'psk',
                encryptedProfile: 'ep',
                addedAt: 1000,
                updatedAt: 1000
            }

            db.saveContact(contact)

            expect(db.getContact('specific-key')).toEqual(contact)
            expect(db.getContact('nonexistent')).toBeNull()
        })

        it('should update existing contact', () => {
            const contact1: StoredContact = {
                identityKey: 'contact-key',
                profilePublicKey: 'ppk1',
                profileSecretKey: 'psk1',
                encryptedProfile: 'ep1',
                addedAt: 1000,
                updatedAt: 1000
            }

            const contact2: StoredContact = {
                identityKey: 'contact-key',
                profilePublicKey: 'ppk2',
                profileSecretKey: 'psk2',
                encryptedProfile: 'ep2',
                addedAt: 1000,
                updatedAt: 2000
            }

            db.saveContact(contact1)
            db.saveContact(contact2)

            const contacts = db.getContacts()
            expect(contacts).toHaveLength(1)
            expect(contacts[0].profilePublicKey).toBe('ppk2')
        })

        it('should delete contact and messages', () => {
            const contact: StoredContact = {
                identityKey: 'delete-me',
                profilePublicKey: 'ppk',
                profileSecretKey: 'psk',
                encryptedProfile: 'ep',
                addedAt: 1000,
                updatedAt: 1000
            }

            const message: StoredMessage = {
                id: 'msg-1',
                conversationId: 'delete-me',
                isOutgoing: false,
                text: 'Hello',
                createdAt: 1000,
                read: false
            }

            db.saveContact(contact)
            db.saveMessage(message)

            expect(db.getMessages('delete-me')).toHaveLength(1)

            db.deleteContact('delete-me')

            expect(db.getContact('delete-me')).toBeNull()
            expect(db.getMessages('delete-me')).toHaveLength(0)
        })
    })

    describe('Messages', () => {
        beforeEach(() => {
            // Add a contact first (foreign key constraint)
            db.saveContact({
                identityKey: 'peer-1',
                profilePublicKey: 'ppk',
                profileSecretKey: 'psk',
                encryptedProfile: 'ep',
                addedAt: 1000,
                updatedAt: 1000
            })
        })

        it('should return empty array initially', () => {
            expect(db.getMessages('peer-1')).toEqual([])
            expect(db.hasMessage('missing')).toBe(false)
        })

        it('should save and retrieve message', () => {
            const message: StoredMessage = {
                id: 'msg-1',
                conversationId: 'peer-1',
                isOutgoing: true,
                text: 'Hello world',
                createdAt: 1000,
                read: true
            }

            db.saveMessage(message)

            const messages = db.getMessages('peer-1')
            expect(messages).toHaveLength(1)
            expect(messages[0]).toEqual(message)
            expect(db.hasMessage('msg-1')).toBe(true)
        })

        it('should save and retrieve attachments', () => {
            const message: StoredMessage = {
                id: 'msg-attach',
                conversationId: 'peer-1',
                isOutgoing: false,
                text: 'With attachments',
                createdAt: 2000,
                read: false,
                attachments: [
                    {
                        fileName: 'test.txt',
                        hash: 'deadbeef',
                        iv: 'iv-base64',
                        key: 'key-base64',
                        ciphertext: 'cipher-base64'
                    }
                ]
            }

            db.saveMessage(message)

            const messages = db.getMessages('peer-1')
            expect(messages).toHaveLength(1)
            expect(messages[0].attachments).toEqual(message.attachments)

            const attachment = db.getAttachment('msg-attach', 'test.txt')
            expect(attachment).toEqual(message.attachments?.[0])
        })

        it('should return messages in chronological order', () => {
            for (let i = 1; i <= 5; i++) {
                db.saveMessage({
                    id: `msg-${i}`,
                    conversationId: 'peer-1',
                    isOutgoing: i % 2 === 0,
                    text: `Message ${i}`,
                    createdAt: i * 1000,
                    read: false
                })
            }

            const messages = db.getMessages('peer-1')
            expect(messages).toHaveLength(5)
            expect(messages[0].text).toBe('Message 1')
            expect(messages[4].text).toBe('Message 5')
        })

        it('should mark messages as read', () => {
            db.saveMessage({
                id: 'msg-1',
                conversationId: 'peer-1',
                isOutgoing: false,
                text: 'Unread message',
                createdAt: 1000,
                read: false
            })

            expect(db.getMessages('peer-1')[0].read).toBe(false)

            db.markMessagesRead('peer-1')

            expect(db.getMessages('peer-1')[0].read).toBe(true)
        })

        it('should mark messages as read by id', () => {
            db.saveMessage({
                id: 'msg-1',
                conversationId: 'peer-1',
                isOutgoing: false,
                text: 'Unread message 1',
                createdAt: 1000,
                read: false
            })
            db.saveMessage({
                id: 'msg-2',
                conversationId: 'peer-1',
                isOutgoing: false,
                text: 'Unread message 2',
                createdAt: 2000,
                read: false
            })

            db.markMessagesReadById(['msg-2'])

            const messages = db.getMessages('peer-1')
            const msg1 = messages.find(message => message.id === 'msg-1')
            const msg2 = messages.find(message => message.id === 'msg-2')
            expect(msg1?.read).toBe(false)
            expect(msg2?.read).toBe(true)
        })

        it('should return unread incoming messages', () => {
            db.saveMessage({ id: 'm1', conversationId: 'peer-1', isOutgoing: false, text: 'first', createdAt: 1, read: false })
            db.saveMessage({ id: 'm2', conversationId: 'peer-1', isOutgoing: true, text: 'outgoing', createdAt: 2, read: false })
            db.saveMessage({ id: 'm3', conversationId: 'peer-1', isOutgoing: false, text: 'second', createdAt: 3, read: false })
            db.saveMessage({ id: 'm4', conversationId: 'peer-1', isOutgoing: false, text: 'read', createdAt: 4, read: true })

            const unread = db.getUnreadMessages()
            expect(unread.map(msg => msg.id)).toEqual(['m1', 'm3'])
        })

        it('should filter unread messages by conversation', () => {
            db.saveContact({
                identityKey: 'peer-2',
                profilePublicKey: 'ppk',
                profileSecretKey: 'psk2',
                encryptedProfile: 'ep',
                addedAt: 1000,
                updatedAt: 1000
            })

            db.saveMessage({ id: 'm1', conversationId: 'peer-1', isOutgoing: false, text: 'peer-1', createdAt: 1, read: false })
            db.saveMessage({ id: 'm2', conversationId: 'peer-2', isOutgoing: false, text: 'peer-2', createdAt: 2, read: false })

            const unread = db.getUnreadMessages('peer-2')
            expect(unread.map(msg => msg.id)).toEqual(['m2'])
        })

        it('should get unread counts', () => {
            db.saveContact({
                identityKey: 'peer-2',
                profilePublicKey: 'ppk',
                profileSecretKey: 'psk2',
                encryptedProfile: 'ep',
                addedAt: 1000,
                updatedAt: 1000
            })

            // Peer-1: 2 unread incoming
            db.saveMessage({ id: 'm1', conversationId: 'peer-1', isOutgoing: false, text: 'a', createdAt: 1, read: false })
            db.saveMessage({ id: 'm2', conversationId: 'peer-1', isOutgoing: false, text: 'b', createdAt: 2, read: false })
            db.saveMessage({ id: 'm3', conversationId: 'peer-1', isOutgoing: true, text: 'c', createdAt: 3, read: false })

            // Peer-2: 1 unread incoming
            db.saveMessage({ id: 'm4', conversationId: 'peer-2', isOutgoing: false, text: 'd', createdAt: 4, read: false })
            db.saveMessage({ id: 'm5', conversationId: 'peer-2', isOutgoing: false, text: 'e', createdAt: 5, read: true })

            const counts = db.getUnreadCounts()
            expect(counts.get('peer-1')).toBe(2)
            expect(counts.get('peer-2')).toBe(1)
        })

        it('should get last messages for each conversation', () => {
            db.saveContact({
                identityKey: 'peer-2',
                profilePublicKey: 'ppk',
                profileSecretKey: 'psk2',
                encryptedProfile: 'ep',
                addedAt: 1000,
                updatedAt: 1000
            })

            db.saveMessage({ id: 'm1', conversationId: 'peer-1', isOutgoing: false, text: 'First', createdAt: 1000, read: true })
            db.saveMessage({ id: 'm2', conversationId: 'peer-1', isOutgoing: true, text: 'Last peer-1', createdAt: 3000, read: true })
            db.saveMessage({ id: 'm3', conversationId: 'peer-2', isOutgoing: false, text: 'Last peer-2', createdAt: 2000, read: false })

            const lastMessages = db.getLastMessages()
            expect(lastMessages.get('peer-1')?.text).toBe('Last peer-1')
            expect(lastMessages.get('peer-2')?.text).toBe('Last peer-2')
        })
    })
})
