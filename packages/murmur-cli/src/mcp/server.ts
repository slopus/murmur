/**
 * Murmur MCP Server (stdio).
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js'
import { MurmurEngine } from '../engine/engine.js'
import { getDbPath } from '../storage/database.js'
import type { Contact, StoredMessage } from '../storage/types.js'
import { decodeBase58, decodeBase64, encodeBase58, encodeBase64 } from '../encryption/crypto/utils.js'
import { publicKeyFromPrivate } from '../encryption/crypto/dh.js'
import { decryptProfile } from '../engine/profile.js'
import { logger } from '../logger.js'

type ToolResult = { content: Array<{ type: 'text'; text: string }> }

function isBase58(value: string): boolean {
    return /^[1-9A-HJ-NP-Za-km-z]+$/.test(value)
}

function decodeProfileId(value: string): Uint8Array {
    const trimmed = value.trim()
    if (!trimmed) {
        throw new Error('Profile ID cannot be empty')
    }
    if (!isBase58(trimmed)) {
        throw new Error('Profile ID must be base58')
    }
    const bytes = decodeBase58(trimmed)
    if (bytes.length !== 32) {
        throw new Error('Invalid profile ID length')
    }
    return bytes
}

function formatProfileId(profileSecretKey: string): string {
    return encodeBase58(decodeBase64(profileSecretKey, 'base64url'))
}

function formatIdentityKey(identityKey: string): string {
    return encodeBase58(decodeBase64(identityKey))
}

function resolveContactByProfileId(engine: MurmurEngine, profileId: string): Contact {
    const profileSecretKeyBytes = decodeProfileId(profileId)
    const profilePublicKey = encodeBase64(publicKeyFromPrivate(profileSecretKeyBytes))
    const contact = engine.getContacts().find(item => item.profilePublicKey === profilePublicKey)
    if (!contact) {
        throw new Error('Contact not found. Add the contact first.')
    }
    return contact
}

function toProfileSecretBase64(profileId: string): string {
    const profileSecretKeyBytes = decodeProfileId(profileId)
    return encodeBase64(profileSecretKeyBytes, 'base64url')
}

function formatMessage(
    message: StoredMessage,
    contacts: Map<string, Contact>,
    profileId: string
): Record<string, unknown> {
    const contact = contacts.get(message.conversationId)
    const from = message.isOutgoing
        ? profileId
        : contact?.profileSecretKey
            ? formatProfileId(contact.profileSecretKey)
            : formatIdentityKey(message.conversationId)
    const to = message.isOutgoing
        ? contact?.profileSecretKey
            ? formatProfileId(contact.profileSecretKey)
            : formatIdentityKey(message.conversationId)
        : profileId

    return {
        id: message.id,
        out: message.isOutgoing,
        from,
        to,
        text: message.text,
        createdAt: message.createdAt,
        attachments: message.attachments?.map(attachment => attachment.fileName) ?? []
    }
}

function textResult(payload: unknown): ToolResult {
    return {
        content: [
            {
                type: 'text',
                text: JSON.stringify(payload, null, 2)
            }
        ]
    }
}

export async function startMcpServer(): Promise<void> {
    const rootDir = process.env.MURMUR_ROOT
    const apiBaseUrl = process.env.MURMUR_API_BASE_URL
    const engine = new MurmurEngine(getDbPath(rootDir), apiBaseUrl)

    const ensureInitialized = async (): Promise<void> => {
        const initialized = await engine.initialize()
        if (!initialized) {
            throw new Error('No account found. Run `murmur sign-in` first.')
        }
    }

    const server = new Server({
        name: 'murmur',
        version: '0.1.0',
        capabilities: {
            tools: {}
        }
    })

    server.setRequestHandler(ListToolsRequestSchema, async () => ({
        tools: [
            {
                name: 'contacts.list',
                description: 'List contacts.',
                inputSchema: { type: 'object', properties: {}, additionalProperties: false }
            },
            {
                name: 'contacts.add',
                description: 'Add a contact by profile ID (base58).',
                inputSchema: {
                    type: 'object',
                    properties: { id: { type: 'string' } },
                    required: ['id'],
                    additionalProperties: false
                }
            },
            {
                name: 'contacts.remove',
                description: 'Remove a contact by profile ID (base58).',
                inputSchema: {
                    type: 'object',
                    properties: { id: { type: 'string' } },
                    required: ['id'],
                    additionalProperties: false
                }
            },
            {
                name: 'contacts.block',
                description: 'Block a contact by profile ID (base58).',
                inputSchema: {
                    type: 'object',
                    properties: { id: { type: 'string' } },
                    required: ['id'],
                    additionalProperties: false
                }
            },
            {
                name: 'contacts.unblock',
                description: 'Unblock a contact by profile ID (base58).',
                inputSchema: {
                    type: 'object',
                    properties: { id: { type: 'string' } },
                    required: ['id'],
                    additionalProperties: false
                }
            },
            {
                name: 'messages.send',
                description: 'Send a message to a contact.',
                inputSchema: {
                    type: 'object',
                    properties: {
                        to: { type: 'string' },
                        message: { type: 'string' },
                        attachments: { type: 'array', items: { type: 'string' } }
                    },
                    required: ['to', 'message'],
                    additionalProperties: false
                }
            },
            {
                name: 'messages.sync',
                description: 'Sync inbox and return new messages.',
                inputSchema: {
                    type: 'object',
                    properties: {
                        with: { type: 'string' }
                    },
                    additionalProperties: false
                }
            },
            {
                name: 'messages.list',
                description: 'List recent messages with a contact.',
                inputSchema: {
                    type: 'object',
                    properties: {
                        with: { type: 'string' },
                        limit: { type: 'number' }
                    },
                    required: ['with'],
                    additionalProperties: false
                }
            },
            {
                name: 'messages.ack',
                description: 'Mark message IDs as read locally.',
                inputSchema: {
                    type: 'object',
                    properties: {
                        ids: { type: 'array', items: { type: 'string' } }
                    },
                    required: ['ids'],
                    additionalProperties: false
                }
            },
            {
                name: 'profile.me',
                description: 'Fetch the local profile.',
                inputSchema: { type: 'object', properties: {}, additionalProperties: false }
            },
            {
                name: 'settings.configure',
                description: 'Update settings. permissions = default-allow or default-deny.',
                inputSchema: {
                    type: 'object',
                    properties: {
                        permissions: { type: 'string' }
                    },
                    additionalProperties: false
                }
            }
        ]
    }))

    server.setRequestHandler(CallToolRequestSchema, async request => {
        await ensureInitialized()
        const args = (request.params.arguments ?? {}) as Record<string, unknown>
        const account = engine.getAccount()
        if (!account) {
            throw new Error('Account data missing.')
        }
        const profileId = formatProfileId(account.profileSecretKey)
        const contacts = new Map(engine.getContacts().map(contact => [contact.identityKey, contact]))

        switch (request.params.name) {
            case 'contacts.list': {
                const entries = engine.getContacts().map(contact => ({
                    id: contact.profileSecretKey ? formatProfileId(contact.profileSecretKey) : formatIdentityKey(contact.identityKey),
                    identityKey: formatIdentityKey(contact.identityKey),
                    firstName: contact.firstName,
                    lastName: contact.lastName,
                    blocked: contact.blocked,
                    addedAt: contact.addedAt,
                    updatedAt: contact.updatedAt
                }))
                return textResult({ contacts: entries })
            }
            case 'contacts.add': {
                const id = args.id
                if (typeof id !== 'string') {
                    throw new Error('Missing contact id')
                }
                const contact = await engine.addContactByProfileSecret(toProfileSecretBase64(id))
                return textResult({
                    contact: {
                        id: contact.profileSecretKey ? formatProfileId(contact.profileSecretKey) : formatIdentityKey(contact.identityKey),
                        identityKey: formatIdentityKey(contact.identityKey),
                        firstName: contact.firstName,
                        lastName: contact.lastName,
                        blocked: contact.blocked
                    }
                })
            }
            case 'contacts.remove': {
                const id = args.id
                if (typeof id !== 'string') {
                    throw new Error('Missing contact id')
                }
                engine.removeContactByProfileSecret(toProfileSecretBase64(id))
                return textResult({ removed: id })
            }
            case 'contacts.block':
            case 'contacts.unblock': {
                const id = args.id
                if (typeof id !== 'string') {
                    throw new Error('Missing contact id')
                }
                const blocked = request.params.name === 'contacts.block'
                const contact = engine.updateContactBlocked(toProfileSecretBase64(id), blocked)
                return textResult({
                    contact: {
                        id: contact.profileSecretKey ? formatProfileId(contact.profileSecretKey) : formatIdentityKey(contact.identityKey),
                        identityKey: formatIdentityKey(contact.identityKey),
                        firstName: contact.firstName,
                        lastName: contact.lastName,
                        blocked: contact.blocked
                    }
                })
            }
            case 'messages.send': {
                const to = args.to
                const message = args.message
                const attachments = Array.isArray(args.attachments)
                    ? args.attachments.filter((item): item is string => typeof item === 'string')
                    : []
                if (typeof to !== 'string' || typeof message !== 'string') {
                    throw new Error('Missing to/message')
                }
                const contact = resolveContactByProfileId(engine, to)
                const stored = await engine.sendMessage(contact.identityKey, message, attachments)
                return textResult(formatMessage(stored, contacts, profileId))
            }
            case 'messages.sync': {
                const withId = args.with
                let filterIdentity: string | undefined
                if (typeof withId === 'string') {
                    filterIdentity = resolveContactByProfileId(engine, withId).identityKey
                }
                const result = await engine.sync()
                const newMessages = result.newMessages
                    .filter(message => (filterIdentity ? message.conversationId === filterIdentity : true))
                    .map(message => formatMessage(message, contacts, profileId))
                return textResult({ newMessages })
            }
            case 'messages.list': {
                const withId = args.with
                const limit = typeof args.limit === 'number' && Number.isFinite(args.limit) ? args.limit : 20
                if (typeof withId !== 'string') {
                    throw new Error('Missing contact id')
                }
                const contact = resolveContactByProfileId(engine, withId)
                const messages = engine.getMessages(contact.identityKey, limit)
                    .map(message => formatMessage(message, contacts, profileId))
                return textResult({ messages })
            }
            case 'messages.ack': {
                const ids = args.ids
                if (!Array.isArray(ids) || ids.length === 0) {
                    throw new Error('Missing message IDs')
                }
                const messageIds = ids.filter((item): item is string => typeof item === 'string')
                await engine.acknowledgeMessages(messageIds)
                return textResult({ acknowledged: messageIds.length })
            }
            case 'profile.me': {
                const profileSecretKeyBytes = decodeBase64(account.profileSecretKey, 'base64url')
                const profile = decryptProfile(account.encryptedProfile, profileSecretKeyBytes)
                return textResult({
                    id: profileId,
                    profile
                })
            }
            case 'settings.configure': {
                if (typeof args.permissions === 'string') {
                    if (args.permissions === 'default-allow') {
                        engine.setDefaultAllow(true)
                    } else if (args.permissions === 'default-deny') {
                        engine.setDefaultAllow(false)
                    } else {
                        throw new Error(`Unknown permissions value: ${args.permissions}`)
                    }
                }
                return textResult(engine.getSettings())
            }
            default:
                throw new Error(`Unknown tool: ${request.params.name}`)
        }
    })

    const transport = new StdioServerTransport()
    await server.connect(transport)

    const shutdown = async () => {
        try {
            engine.close()
        } catch (error) {
            logger.error({ error }, 'Failed to close engine')
        }
        process.exit(0)
    }

    process.on('SIGINT', shutdown)
    process.on('SIGTERM', shutdown)
}
