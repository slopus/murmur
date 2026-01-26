#!/usr/bin/env node
/**
 * Murmur CLI Entry Point.
 *
 * Provides non-interactive commands for account setup and messaging.
 */

import { MurmurEngine } from './engine/engine.js'
import { MurmurApi } from './engine/api.js'
import { decryptProfile } from './engine/profile.js'
import type { Contact, StoredMessage, HookType } from './storage/types.js'
import { getDbPath } from './storage/database.js'
import { decodeBase64, encodeBase64, decodeBase58, encodeBase58 } from './encryption/crypto/utils.js'
import { publicKeyFromPrivate } from './encryption/crypto/dh.js'
import { logger } from './logger.js'

/**
 * Parsed CLI arguments.
 */
interface ParsedArgs {
    command: string | null
    options: Record<string, string | boolean | string[]>
    positionals: string[]
}

/**
 * Parse CLI arguments into command, options, and positionals.
 */
function parseArgs(args: string[]): ParsedArgs {
    let command: string | null = null
    const options: Record<string, string | boolean | string[]> = {}
    const positionals: string[] = []

    const pushOption = (key: string, value: string): void => {
        const existing = options[key]
        if (existing === undefined) {
            options[key] = value
            return
        }
        if (Array.isArray(existing)) {
            existing.push(value)
            return
        }
        if (typeof existing === 'string') {
            options[key] = [existing, value]
            return
        }
        options[key] = value
    }

    for (let i = 0; i < args.length; i += 1) {
        const arg = args[i]

        if (arg === '-h' || arg === '--help') {
            options.help = true
            continue
        }

        if (arg === '-n') {
            const next = args[i + 1]
            if (next && !next.startsWith('-')) {
                options.limit = next
                i += 1
                continue
            }
        }

        if (arg.startsWith('--')) {
            const trimmed = arg.slice(2)
            const eqIndex = trimmed.indexOf('=')
            if (eqIndex >= 0) {
                const key = trimmed.slice(0, eqIndex)
                const value = trimmed.slice(eqIndex + 1)
                pushOption(key, value)
            } else {
                const next = args[i + 1]
                if (next && !next.startsWith('-')) {
                    pushOption(trimmed, next)
                    i += 1
                } else {
                    options[trimmed] = true
                }
            }
            continue
        }

        if (!command) {
            command = arg
        } else {
            positionals.push(arg)
        }
    }

    return { command, options, positionals }
}

/**
 * Read a string option from args or environment.
 */
function readStringOption(
    options: Record<string, string | boolean | string[]>,
    name: string,
    envName?: string
): string | undefined {
    const value = options[name]
    if (typeof value === 'string' && value.trim().length > 0) {
        return value
    }
    if (Array.isArray(value) && value.length > 0 && value[0].trim().length > 0) {
        return value[0]
    }

    if (envName) {
        const envValue = process.env[envName]
        if (envValue && envValue.trim().length > 0) {
            return envValue
        }
    }

    return undefined
}

/**
 * Read a required string option or throw.
 */
function requireStringOption(
    options: Record<string, string | boolean | string[]>,
    name: string,
    envName?: string
): string {
    const value = readStringOption(options, name, envName)
    if (!value) {
        const envHint = envName ? ` or ${envName}` : ''
        throw new Error(`Missing --${name}${envHint}`)
    }
    return value
}

/**
 * Read a numeric option from args or environment.
 */
function readNumberOption(
    options: Record<string, string | boolean | string[]>,
    name: string,
    envName?: string
): number | undefined {
    const raw = readStringOption(options, name, envName)
    if (!raw) return undefined

    const parsed = Number.parseInt(raw, 10)
    if (!Number.isFinite(parsed)) {
        throw new Error(`Invalid --${name} value: ${raw}`)
    }
    return parsed
}

/**
 * Read a boolean option from args or environment.
 */
function readBooleanOption(
    options: Record<string, string | boolean | string[]>,
    name: string,
    envName?: string
): boolean {
    const parseBoolean = (value: string): boolean => {
        const normalized = value.trim().toLowerCase()
        if (['1', 'true', 'yes', 'y'].includes(normalized)) {
            return true
        }
        if (['0', 'false', 'no', 'n'].includes(normalized)) {
            return false
        }
        throw new Error(`Invalid --${name} value: ${value}`)
    }

    const raw = options[name]
    if (typeof raw === 'boolean') {
        return raw
    }
    if (typeof raw === 'string') {
        return parseBoolean(raw)
    }

    if (envName) {
        const envValue = process.env[envName]
        if (envValue !== undefined) {
            return parseBoolean(envValue)
        }
    }

    return false
}

/**
 * Read a string array option from args.
 */
function readStringArrayOption(
    options: Record<string, string | boolean | string[]>,
    name: string
): string[] {
    const value = options[name]
    if (typeof value === 'string') {
        return value.trim().length > 0 ? [value] : []
    }
    if (Array.isArray(value)) {
        return value.map(item => item.trim()).filter(item => item.length > 0)
    }
    return []
}

/**
 * Format a timestamp for CLI output.
 */
function formatTimestamp(value: number): string {
    return new Date(value).toISOString()
}

/**
 * Format a contact label for display.
 */
function formatContact(contact: Contact): string {
    const name = [contact.firstName, contact.lastName].filter(Boolean).join(' ')
    const identity = formatIdentityKey(contact.identityKey)
    if (name.length > 0) {
        return `${name} (${identity})`
    }
    return identity
}

/**
 * Check if a string looks like base58.
 */
function isBase58(value: string): boolean {
    return /^[1-9A-HJ-NP-Za-km-z]+$/.test(value)
}

/**
 * Decode an identity key string to raw bytes.
 */
function decodeIdentityKey(value: string): Uint8Array {
    const trimmed = value.trim()
    if (!trimmed) {
        throw new Error('Identity key cannot be empty')
    }

    const hasBase64Hints = /[+/=]/.test(trimmed)
    const hasBase64UrlHints = /[-_]/.test(trimmed)

    if (isBase58(trimmed) && !hasBase64Hints && !hasBase64UrlHints) {
        const bytes = decodeBase58(trimmed)
        if (bytes.length === 32) {
            return bytes
        }
    }

    try {
        const bytes = decodeBase64(trimmed)
        if (bytes.length === 32) {
            return bytes
        }
    } catch {
        // Ignore and try next format.
    }

    try {
        const bytes = decodeBase64(trimmed, 'base64url')
        if (bytes.length === 32) {
            return bytes
        }
    } catch {
        // Ignore and try base58.
    }

    if (isBase58(trimmed)) {
        const bytes = decodeBase58(trimmed)
        if (bytes.length === 32) {
            return bytes
        }
    }

    throw new Error('Invalid identity key format')
}

/**
 * Decode a profile secret key (base64url, no padding).
 */
function decodeProfileSecretKey(value: string): Uint8Array {
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

/**
 * Format a profile secret key (base64url) for display.
 */
function formatProfileSecretKey(profileSecretKey: string): string {
    return encodeBase58(decodeBase64(profileSecretKey, 'base64url'))
}

/**
 * Decode the locally stored profile secret key (base64url).
 */
function decodeStoredProfileSecretKey(profileSecretKey: string): Uint8Array {
    const bytes = decodeBase64(profileSecretKey, 'base64url')
    if (bytes.length !== 32) {
        throw new Error('Invalid stored profile secret key')
    }
    return bytes
}

/**
 * Resolve a contact by profile secret key.
 */
function resolveContactByProfileSecret(engine: MurmurEngine, profileSecretKey: string): Contact {
    const profileSecretKeyBytes = decodeProfileSecretKey(profileSecretKey)
    const profilePublicKey = encodeBase64(publicKeyFromPrivate(profileSecretKeyBytes))
    const contact = engine.getContacts().find(item => item.profilePublicKey === profilePublicKey)
    if (!contact) {
        throw new Error('Contact not found. Add contact with `murmur contacts add <id>` first.')
    }
    return contact
}

/**
 * Normalize an identity key string to base64.
 */
function normalizeIdentityKey(value: string): string {
    return encodeBase64(decodeIdentityKey(value))
}

/**
 * Format a base64 identity key as base58.
 */
function formatIdentityKey(identityKey: string): string {
    return encodeBase58(decodeBase64(identityKey))
}

/**
 * Parse a hook type.
 */
function parseHookType(value: string): HookType {
    if (value === 'message') {
        return value
    }
    throw new Error(`Unsupported hook type: ${value}`)
}

/**
 * Print CLI usage help.
 */
function printUsage(): void {
    const lines = [
        'Usage:',
        '  murmur sign-in [--first-name <name>] [--last-name <name>]',
        '  murmur me',
        '  murmur delete-account --confirm',
        '  murmur contacts',
        '  murmur contacts add <id>',
        '  murmur contacts remove <id>',
        '  murmur contacts block <id>',
        '  murmur contacts unblock <id>',
        '  murmur configure [default-allow|default-deny]',
        '  murmur profile <profile-secret>',
        '  murmur send --to <id> --message <text> [--attach <path> ...]',
        '  murmur sync [--with <id>] [--realtime] [--timeout <ms>] [--webhook <url>] [--webhook-body <json>]',
        '  murmur messages --with <id> [--limit <n>]',
        '  murmur ack <messageId...>',
        '  murmur attachment --message <id> --name <file> --out <path>',
        '  murmur hooks add message <path> [--arg <value> ...]',
        '  murmur hooks remove <id>'
    ]

    console.log(lines.join('\n'))
}

/**
 * Ensure the engine is initialized with an existing account.
 */
async function requireInitialized(engine: MurmurEngine): Promise<void> {
    const initialized = await engine.initialize()
    if (!initialized) {
        throw new Error('No account found. Run `murmur sign-in` first.')
    }
}

/**
 * Print account information.
 */
function printAccountSummary(prefix: string, account: { profileSecretKey: string; firstName: string; lastName?: string }): void {
    const name = [account.firstName, account.lastName].filter(Boolean).join(' ')
    console.log(prefix)
    console.log(`ID: ${formatProfileSecretKey(account.profileSecretKey)}`)
    console.log(`Name: ${name}`)
}

/**
 * Print a message line.
 */
function formatName(firstName?: string, lastName?: string, fallback: string = 'Unknown'): string {
    const name = [firstName, lastName].filter(Boolean).join(' ')
    return name.length > 0 ? name : fallback
}

function formatSenderId(contact: Contact | undefined, fallbackIdentityKey: string): string {
    if (contact?.profileSecretKey) {
        return formatProfileSecretKey(contact.profileSecretKey)
    }
    return `Unknown (${formatIdentityKey(fallbackIdentityKey)})`
}

function isAuthErrorMessage(message: string | undefined): boolean {
    if (!message) {
        return false
    }
    const normalized = message.toLowerCase()
    return normalized.includes('not authenticated') || normalized.includes('token')
}

function formatWebhookSenderId(contact: Contact | undefined, fallbackIdentityKey: string): string {
    if (contact?.profileSecretKey) {
        return formatProfileSecretKey(contact.profileSecretKey)
    }
    return formatIdentityKey(fallbackIdentityKey)
}

function printMessageBlock(message: StoredMessage, senderId: string, senderName: string): void {
    const attachments = message.attachments
    const attachmentNames = attachments?.map(attachment => attachment.fileName) ?? []
    console.log('----')
    console.log(`Message ID: ${message.id}`)
    console.log(`Sender ID: ${senderId}`)
    console.log(`Sender Name: ${senderName}`)
    console.log(`Date: ${formatTimestamp(message.createdAt)}`)
    if (attachmentNames.length > 0) {
        console.log(`Attachments: ${attachmentNames.join(', ')}`)
    }
    console.log(message.text)
    console.log('----')
}

function printUnreadMessages(
    engine: MurmurEngine,
    filterContact: Contact | undefined,
    printedIds: Set<string> | null,
    showEmpty: boolean
): number {
    const unreadMessages = engine.getUnreadMessages(filterContact?.identityKey)
    if (unreadMessages.length === 0) {
        if (showEmpty) {
            logger.info('No unread messages.')
        }
        return 0
    }

    const contacts = new Map(
        engine.getContacts().map(contact => [contact.identityKey, contact])
    )
    const account = engine.getAccount()
    if (!account) {
        throw new Error('Account data missing.')
    }

    let printed = 0
    for (const message of unreadMessages) {
        if (printedIds && printedIds.has(message.id)) {
            continue
        }
        const contact = filterContact ?? contacts.get(message.conversationId)
        const senderId = message.isOutgoing
            ? formatProfileSecretKey(account.profileSecretKey)
            : formatSenderId(contact, message.conversationId)
        const senderName = message.isOutgoing
            ? formatName(account.firstName, account.lastName, 'You')
            : formatName(contact?.firstName, contact?.lastName, formatIdentityKey(message.conversationId))
        printMessageBlock(message, senderId, senderName)
        if (printedIds) {
            printedIds.add(message.id)
        }
        printed += 1
    }

    return printed
}

type WebhookContext = {
    event: string
    messageId: string
    senderId: string
    senderIdentityKey: string
    senderName: string
    receivedAt: number
    hasAttachments: boolean
}

function resolveWebhookTemplate(value: unknown, context: WebhookContext): unknown {
    if (typeof value === 'string') {
        const exactMatch = value.match(/^{{\s*([a-zA-Z0-9_]+)\s*}}$/)
        if (exactMatch) {
            const key = exactMatch[1] as keyof WebhookContext
            return context[key] ?? value
        }
        return value.replace(/{{\s*([a-zA-Z0-9_]+)\s*}}/g, (_match, key) => {
            const typedKey = key as keyof WebhookContext
            const replacement = context[typedKey]
            return replacement === undefined ? '' : String(replacement)
        })
    }
    if (Array.isArray(value)) {
        return value.map(item => resolveWebhookTemplate(item, context))
    }
    if (value && typeof value === 'object') {
        const result: Record<string, unknown> = {}
        for (const [entryKey, entryValue] of Object.entries(value)) {
            result[entryKey] = resolveWebhookTemplate(entryValue, context)
        }
        return result
    }
    return value
}

async function postWebhook(url: string, payload: unknown): Promise<void> {
    const response = await fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
    })

    if (!response.ok) {
        const errorText = await response.text().catch(() => '')
        throw new Error(errorText || `HTTP ${response.status}`)
    }
}

async function emitWebhook(
    webhookUrl: string | undefined,
    webhookTemplate: unknown,
    engine: MurmurEngine,
    messages: StoredMessage[],
    filterContact: Contact | undefined
): Promise<void> {
    if (!webhookUrl || messages.length === 0) {
        return
    }

    const contacts = new Map(
        engine.getContacts().map(contact => [contact.identityKey, contact])
    )

    for (const message of messages) {
        if (message.isOutgoing) {
            continue
        }
        if (filterContact && message.conversationId !== filterContact.identityKey) {
            continue
        }

        const contact = contacts.get(message.conversationId)
        const context: WebhookContext = {
            event: 'message',
            messageId: message.id,
            senderId: formatWebhookSenderId(contact, message.conversationId),
            senderIdentityKey: message.conversationId,
            senderName: formatName(contact?.firstName, contact?.lastName, 'Unknown'),
            receivedAt: message.createdAt,
            hasAttachments: Boolean(message.attachments && message.attachments.length > 0)
        }
        const payload = resolveWebhookTemplate(webhookTemplate, context)

        try {
            await postWebhook(webhookUrl, payload)
        } catch (error) {
            const messageText = error instanceof Error ? error.message : String(error)
            logger.error(`Webhook failed for ${message.id}: ${messageText}`)
        }
    }
}

async function waitWithAbort(delayMs: number, signal: AbortSignal): Promise<void> {
    if (delayMs <= 0) {
        return
    }
    if (signal.aborted) {
        throw new Error('Aborted')
    }
    await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => {
            cleanup()
            resolve()
        }, delayMs)

        const onAbort = () => {
            cleanup()
            reject(new Error('Aborted'))
        }

        const cleanup = () => {
            clearTimeout(timer)
            signal.removeEventListener('abort', onAbort)
        }

        signal.addEventListener('abort', onAbort)
    })
}

/**
 * Run the CLI command.
 */
async function run(): Promise<void> {
    const parsed = parseArgs(process.argv.slice(2))

    if (!parsed.command || parsed.options.help === true || parsed.command === 'help') {
        printUsage()
        return
    }

    logger.info('Welcome to Murmur! End-To-End encrypted messenger for AI Agents.')

    const rootDir = readStringOption(parsed.options, 'root', 'MURMUR_ROOT')
    const apiBaseUrl =
        readStringOption(parsed.options, 'api', 'MURMUR_API_BASE_URL') ??
        readStringOption(parsed.options, 'api-base-url')

    let engine: MurmurEngine | null = null
    const getEngine = () => {
        if (!engine) {
            engine = new MurmurEngine(getDbPath(rootDir), apiBaseUrl)
        }
        return engine
    }

    try {
        switch (parsed.command) {
            case 'sign-in': {
                const initialized = await getEngine().initialize()
                if (initialized) {
                    const account = getEngine().getAccount()
                    if (!account) {
                        throw new Error('Account data missing.')
                    }
                    printAccountSummary('Signed in with existing account.', account)
                    const authError = getEngine().getAuthError()
                    if (authError) {
                        logger.warn(`Note: server login failed (${authError}). Run \`murmur delete-account --confirm\` then \`murmur sign-in\` to re-register.`)
                    }
                    return
                }

                const firstName = requireStringOption(parsed.options, 'first-name', 'MURMUR_FIRST_NAME')
                const lastName = readStringOption(parsed.options, 'last-name', 'MURMUR_LAST_NAME')
                const account = await getEngine().createAccount(firstName, lastName)
                printAccountSummary('Account created and signed in.', account)
                return
            }
            case 'me': {
                await requireInitialized(getEngine())
                const account = getEngine().getAccount()
                if (!account) {
                    throw new Error('Account data missing.')
                }
                const profileSecretKeyBytes = decodeStoredProfileSecretKey(account.profileSecretKey)
                const profile = decryptProfile(account.encryptedProfile, profileSecretKeyBytes)
                console.log(`ID: ${formatProfileSecretKey(account.profileSecretKey)}`)
                console.log(JSON.stringify(profile, null, 2))
                return
            }
            case 'delete-account': {
                await requireInitialized(getEngine())
                const confirmed = readBooleanOption(parsed.options, 'confirm', 'MURMUR_CONFIRM_DELETE')
                if (!confirmed) {
                    throw new Error('Account deletion requires --confirm or MURMUR_CONFIRM_DELETE=true')
                }
                await getEngine().deleteAccount()
                logger.info('Account deleted.')
                return
            }
            case 'send': {
                await requireInitialized(getEngine())
                const recipientId = requireStringOption(parsed.options, 'to', 'MURMUR_TO')
                const message = requireStringOption(parsed.options, 'message', 'MURMUR_MESSAGE')
                const attachments = readStringArrayOption(parsed.options, 'attach')
                const contact = resolveContactByProfileSecret(getEngine(), recipientId)
                const stored = await getEngine().sendMessage(contact.identityKey, message, attachments)
                logger.info(`Sent ${stored.id} to ${formatContact(contact)} at ${formatTimestamp(stored.createdAt)}`)
                return
            }
            case 'contacts': {
                await requireInitialized(getEngine())
                const action = parsed.positionals[0] ?? 'list'

                if (action === 'list') {
                    const contacts = getEngine().getContacts()
                    if (contacts.length === 0) {
                        logger.info('No contacts.')
                        return
                    }
                    logger.info('Contacts:')
                    for (const contact of contacts) {
                        const name = formatName(contact.firstName, contact.lastName, 'Unknown')
                        const id = contact.profileSecretKey
                            ? formatProfileSecretKey(contact.profileSecretKey)
                            : formatIdentityKey(contact.identityKey)
                        const suffix = contact.blocked ? ' [blocked]' : ''
                        console.log(`${name} (${id})${suffix}`)
                    }
                    return
                }

                if (action === 'add') {
                    const profileSecret = parsed.positionals[1]
                    if (!profileSecret) {
                        throw new Error('Missing contact ID. Usage: murmur contacts add <id>')
                    }
                    const profileSecretBytes = decodeProfileSecretKey(profileSecret)
                    const profileSecretBase64 = encodeBase64(profileSecretBytes, 'base64url')
                    const contact = await getEngine().addContactByProfileSecret(profileSecretBase64)
                    logger.info(`Added contact: ${formatContact(contact)}`)
                    return
                }

                if (action === 'remove') {
                    const profileSecret = parsed.positionals[1]
                    if (!profileSecret) {
                        throw new Error('Missing contact ID. Usage: murmur contacts remove <id>')
                    }
                    const profileSecretBytes = decodeProfileSecretKey(profileSecret)
                    const profileSecretBase64 = encodeBase64(profileSecretBytes, 'base64url')
                    getEngine().removeContactByProfileSecret(profileSecretBase64)
                    logger.info('Contact removed.')
                    return
                }

                if (action === 'block' || action === 'unblock') {
                    const profileSecret = parsed.positionals[1]
                    if (!profileSecret) {
                        throw new Error(`Missing contact ID. Usage: murmur contacts ${action} <id>`)
                    }
                    const profileSecretBytes = decodeProfileSecretKey(profileSecret)
                    const profileSecretBase64 = encodeBase64(profileSecretBytes, 'base64url')
                    const blocked = action === 'block'
                    const contact = getEngine().updateContactBlocked(profileSecretBase64, blocked)
                    logger.info(`${blocked ? 'Blocked' : 'Unblocked'} ${formatContact(contact)}`)
                    return
                }

                throw new Error(`Unknown contacts action: ${action}`)
            }
            case 'configure': {
                await requireInitialized(getEngine())
                const key = parsed.positionals[0]
                if (key) {
                    if (key === 'default-allow') {
                        getEngine().setDefaultAllow(true)
                    } else if (key === 'default-deny') {
                        getEngine().setDefaultAllow(false)
                    } else {
                        throw new Error(`Unknown setting: ${key}`)
                    }
                }
                console.log(JSON.stringify(getEngine().getSettings(), null, 2))
                return
            }
            case 'profile': {
                const positionalSecret = parsed.positionals[0]
                const profileSecret = positionalSecret ?? requireStringOption(parsed.options, 'profile-secret', 'MURMUR_PROFILE_SECRET')
                const profileSecretBytes = decodeProfileSecretKey(profileSecret)
                const profilePublicKey = encodeBase64(publicKeyFromPrivate(profileSecretBytes))
                const api = new MurmurApi(apiBaseUrl)
                const serverProfile = await api.getPublicProfile(profilePublicKey)
                const profile = decryptProfile(serverProfile.encryptedProfile, profileSecretBytes)
                console.log(JSON.stringify(profile, null, 2))
                return
            }
            case 'sync': {
                await requireInitialized(getEngine())
                const webhookUrl = readStringOption(parsed.options, 'webhook')
                const webhookBodyRaw = readStringOption(parsed.options, 'webhook-body')
                if (!webhookUrl && webhookBodyRaw) {
                    throw new Error('Missing --webhook URL')
                }
                if (webhookUrl) {
                    try {
                        new URL(webhookUrl)
                    } catch {
                        throw new Error('Invalid --webhook URL')
                    }
                    if (!webhookBodyRaw) {
                        throw new Error('Missing --webhook-body JSON')
                    }
                }
                let webhookTemplate: unknown = null
                if (webhookBodyRaw) {
                    try {
                        webhookTemplate = JSON.parse(webhookBodyRaw)
                    } catch {
                        throw new Error('Invalid JSON for --webhook-body')
                    }
                }
                const syncResult = await getEngine().sync()
                if (!syncResult.success && syncResult.error) {
                    if (isAuthErrorMessage(syncResult.error)) {
                        throw new Error(`Sync unavailable: ${syncResult.error}`)
                    }
                    logger.error(`Sync unavailable: ${syncResult.error}`)
                }

                const filterId = readStringOption(parsed.options, 'with', 'MURMUR_WITH')
                let filterContact: Contact | undefined
                if (filterId) {
                    filterContact = resolveContactByProfileSecret(getEngine(), filterId)
                }

                const printedIds = new Set<string>()
                await emitWebhook(webhookUrl, webhookTemplate, getEngine(), syncResult.newMessages, filterContact)
                printUnreadMessages(getEngine(), filterContact, printedIds, true)

                const realtime = readBooleanOption(parsed.options, 'realtime')
                if (!realtime) {
                    return
                }

                const timeoutMs = readNumberOption(parsed.options, 'timeout')
                if (timeoutMs !== undefined && timeoutMs <= 0) {
                    throw new Error('Timeout must be a positive number of milliseconds.')
                }

                logger.info('Realtime sync enabled. Press Ctrl+C to stop.')

                const controller = new AbortController()
                let timeoutHandle: ReturnType<typeof setTimeout> | null = null
                if (timeoutMs !== undefined) {
                    timeoutHandle = setTimeout(() => controller.abort(), timeoutMs)
                }

                let syncInFlight = false
                let pendingSync = false

                const triggerSync = async (): Promise<void> => {
                    if (syncInFlight) {
                        pendingSync = true
                        return
                    }
                    syncInFlight = true
                    try {
                        do {
                            pendingSync = false
                            const result = await getEngine().sync()
                            if (!result.success && result.error) {
                                if (isAuthErrorMessage(result.error)) {
                                    throw new Error(`Sync unavailable: ${result.error}`)
                                }
                                logger.error(`Sync unavailable: ${result.error}`)
                            }
                            await emitWebhook(webhookUrl, webhookTemplate, getEngine(), result.newMessages, filterContact)
                            printUnreadMessages(getEngine(), filterContact, printedIds, false)
                        } while (pendingSync)
                    } finally {
                        syncInFlight = false
                    }
                }

                const onSigint = () => {
                    controller.abort()
                }
                process.on('SIGINT', onSigint)

                try {
                    let backoffMs = 1000
                    const maxBackoffMs = 30000

                    while (!controller.signal.aborted) {
                        logger.info('Connecting realtime stream...')
                        try {
                            await getEngine().streamMessages(async event => {
                                if (event.event === 'connected') {
                                    logger.info('Realtime stream connected.')
                                    return
                                }
                                if (event.event === 'ping') {
                                    logger.debug('Realtime stream ping.')
                                    return
                                }
                                if (event.event !== 'message:new') {
                                    logger.debug(`Realtime stream event: ${event.event}`)
                                    return
                                }
                                const data = event.data
                                if (!data || typeof data !== 'object') {
                                    logger.debug('Realtime message event missing payload.')
                                    return
                                }
                                const messageId = (data as { messageId?: unknown }).messageId
                                if (typeof messageId !== 'string' || messageId.length === 0) {
                                    logger.debug('Realtime message event missing messageId.')
                                    return
                                }
                                if (getEngine().hasMessage(messageId)) {
                                    logger.debug(`Realtime message already stored: ${messageId}`)
                                    return
                                }
                                logger.info(`Realtime message received: ${messageId}`)
                                await triggerSync()
                            }, { signal: controller.signal })

                            backoffMs = 1000
                            if (!controller.signal.aborted) {
                                logger.warn('Realtime stream closed. Reconnecting...')
                                await triggerSync()
                            }
                        } catch (error) {
                            if (controller.signal.aborted) {
                                break
                            }
                            const message = error instanceof Error ? error.message : String(error)
                            if (isAuthErrorMessage(message)) {
                                logger.error(`Realtime sync stopped: ${message}`)
                                break
                            }
                            logger.warn(`Realtime sync disconnected: ${message}`)
                        }

                        if (!controller.signal.aborted) {
                            logger.warn(`Retrying realtime stream in ${Math.round(backoffMs / 1000)}s...`)
                            try {
                                await waitWithAbort(backoffMs, controller.signal)
                            } catch {
                                break
                            }
                            backoffMs = Math.min(backoffMs * 2, maxBackoffMs)
                        }
                    }
                } catch (error) {
                    if (!controller.signal.aborted) {
                        throw error
                    }
                } finally {
                    if (timeoutHandle) {
                        clearTimeout(timeoutHandle)
                    }
                    process.off('SIGINT', onSigint)
                }
                return
            }
            case 'messages': {
                await requireInitialized(getEngine())
                const peerId = requireStringOption(parsed.options, 'with', 'MURMUR_WITH')
                const contact = resolveContactByProfileSecret(getEngine(), peerId)
                const limit = readNumberOption(parsed.options, 'limit', 'MURMUR_LIMIT') ?? 20
                if (limit <= 0) {
                    throw new Error('Limit must be a positive number.')
                }

                const label = formatContact(contact)
                const messages = getEngine().getMessages(contact.identityKey, limit)

                if (messages.length === 0) {
                    logger.info(`No messages for ${label}.`)
                    return
                }

                logger.info(`Last ${messages.length} messages for ${label}:`)
                const account = getEngine().getAccount()
                if (!account) {
                    throw new Error('Account data missing.')
                }
                for (const message of messages) {
                    const senderId = message.isOutgoing
                        ? formatProfileSecretKey(account.profileSecretKey)
                        : formatSenderId(contact, message.conversationId)
                    const senderName = message.isOutgoing
                        ? formatName(account.firstName, account.lastName, 'You')
                        : formatName(contact.firstName, contact.lastName)
                    printMessageBlock(message, senderId, senderName)
                }

                return
            }
            case 'ack': {
                await requireInitialized(getEngine())
                const ids = parsed.positionals.filter(value => value.trim().length > 0)
                if (ids.length === 0) {
                    throw new Error('Missing message IDs. Usage: murmur ack <messageId...>')
                }
                await getEngine().acknowledgeMessages(ids)
                logger.info(`Acknowledged ${ids.length} message${ids.length === 1 ? '' : 's'}.`)
                return
            }
            case 'attachment': {
                await requireInitialized(getEngine())
                const messageId = requireStringOption(parsed.options, 'message')
                const fileName = requireStringOption(parsed.options, 'name')
                const outputPath = requireStringOption(parsed.options, 'out')
                getEngine().saveAttachmentToPath(messageId, fileName, outputPath)
                logger.info(`Saved attachment to ${outputPath}`)
                return
            }
            case 'hooks': {
                await requireInitialized(getEngine())
                const action = parsed.positionals[0]
                if (!action) {
                    throw new Error('Missing hooks action. Usage: murmur hooks add|remove ...')
                }

                if (action === 'add') {
                    const typeRaw = parsed.positionals[1]
                    const hookPath = parsed.positionals[2]
                    if (!typeRaw || !hookPath) {
                        throw new Error('Missing hook info. Usage: murmur hooks add message <path> [--arg <value> ...]')
                    }
                    const type = parseHookType(typeRaw)
                    const args = readStringArrayOption(parsed.options, 'arg')
                    const hook = getEngine().addHook(type, hookPath, args)
                    logger.info(`Added hook ${hook.id} (${hook.type})`)
                    return
                }

                if (action === 'remove') {
                    const hookId = parsed.positionals[1]
                    if (!hookId) {
                        throw new Error('Missing hook ID. Usage: murmur hooks remove <id>')
                    }
                    const removed = getEngine().removeHook(hookId)
                    if (removed === 0) {
                        logger.warn(`Hook not found: ${hookId}`)
                    } else {
                        logger.info(`Removed hook ${hookId}`)
                    }
                    return
                }

                throw new Error(`Unknown hooks action: ${action}`)
            }
            default:
                throw new Error(`Unknown command: ${parsed.command}`)
        }
    } finally {
        if (engine !== null) {
            (engine as MurmurEngine).close()
        }
    }
}

run().catch(error => {
    const message = error instanceof Error ? error.message : String(error)
    logger.error(message)
    process.exit(1)
})
