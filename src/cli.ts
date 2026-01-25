#!/usr/bin/env node
/**
 * Murmur CLI Entry Point.
 *
 * Provides non-interactive commands for account setup and messaging.
 */

import { MurmurEngine } from './engine/engine.js'
import { MurmurApi } from './engine/api.js'
import { decryptProfile } from './engine/profile.js'
import type { Contact, StoredMessage } from './storage/types.js'
import { getDbPath } from './storage/database.js'
import { decodeBase64, encodeBase64, decodeBase58, encodeBase58 } from './encryption/crypto/utils.js'
import { publicKeyFromPrivate } from './encryption/crypto/dh.js'

/**
 * Parsed CLI arguments.
 */
interface ParsedArgs {
    command: string | null
    options: Record<string, string | boolean>
    positionals: string[]
}

/**
 * Parse CLI arguments into command, options, and positionals.
 */
function parseArgs(args: string[]): ParsedArgs {
    let command: string | null = null
    const options: Record<string, string | boolean> = {}
    const positionals: string[] = []

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
                options[key] = value
            } else {
                const next = args[i + 1]
                if (next && !next.startsWith('-')) {
                    options[trimmed] = next
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
    options: Record<string, string | boolean>,
    name: string,
    envName?: string
): string | undefined {
    const value = options[name]
    if (typeof value === 'string' && value.trim().length > 0) {
        return value
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
    options: Record<string, string | boolean>,
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
    options: Record<string, string | boolean>,
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
    options: Record<string, string | boolean>,
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
 * Print CLI usage help.
 */
function printUsage(): void {
    const lines = [
        'Usage:',
        '  murmur sign-in [--first-name <name>] [--last-name <name>] [--root <dir>] [--api <url>]',
        '  murmur delete-account --confirm [--root <dir>] [--api <url>]',
        '  murmur add-contact --profile-secret <key> [--root <dir>] [--api <url>]',
        '  murmur profile <profile-secret> [--api <url>]',
        '  murmur send --to <identityKey> --message <text> [--root <dir>] [--api <url>]',
        '  murmur sync [--root <dir>] [--api <url>]',
        '  murmur messages --with <identityKey> [--limit <n>] [--root <dir>] [--api <url>]',
        '',
        'Environment:',
        '  MURMUR_FIRST_NAME, MURMUR_LAST_NAME',
        '  MURMUR_CONFIRM_DELETE',
        '  MURMUR_PROFILE_SECRET',
        '  MURMUR_TO, MURMUR_MESSAGE',
        '  MURMUR_WITH, MURMUR_LIMIT',
        '  MURMUR_ROOT',
        '  MURMUR_API_BASE_URL'
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
function printAccountSummary(prefix: string, account: { identityKey: string; firstName: string; lastName?: string; profilePublicKey: string }): void {
    const name = [account.firstName, account.lastName].filter(Boolean).join(' ')
    console.log(prefix)
    console.log(`Name: ${name}`)
    console.log(`Identity key: ${formatIdentityKey(account.identityKey)}`)
    console.log(`Profile public key: ${encodeBase58(decodeBase64(account.profilePublicKey))}`)
}

/**
 * Print a message line.
 */
function printMessageLine(contactLabel: string, message: StoredMessage): void {
    const direction = message.isOutgoing ? '->' : '<-'
    const timestamp = formatTimestamp(message.createdAt)
    console.log(`${timestamp} ${direction} ${contactLabel}: ${message.text}`)
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
                    return
                }

                const firstName = requireStringOption(parsed.options, 'first-name', 'MURMUR_FIRST_NAME')
                const lastName = readStringOption(parsed.options, 'last-name', 'MURMUR_LAST_NAME')
                const account = await getEngine().createAccount(firstName, lastName)
                printAccountSummary('Account created and signed in.', account)
                return
            }
            case 'delete-account': {
                await requireInitialized(getEngine())
                const confirmed = readBooleanOption(parsed.options, 'confirm', 'MURMUR_CONFIRM_DELETE')
                if (!confirmed) {
                    throw new Error('Account deletion requires --confirm or MURMUR_CONFIRM_DELETE=true')
                }
                await getEngine().deleteAccount()
                console.log('Account deleted.')
                return
            }
            case 'send': {
                await requireInitialized(getEngine())
                const recipient = normalizeIdentityKey(requireStringOption(parsed.options, 'to', 'MURMUR_TO'))
                const message = requireStringOption(parsed.options, 'message', 'MURMUR_MESSAGE')
                const stored = await getEngine().sendMessage(recipient, message)
                console.log(`Sent ${stored.id} to ${formatIdentityKey(recipient)} at ${formatTimestamp(stored.createdAt)}`)
                return
            }
            case 'add-contact': {
                await requireInitialized(getEngine())
                const profileSecret = requireStringOption(parsed.options, 'profile-secret', 'MURMUR_PROFILE_SECRET')
                const contact = await getEngine().addContactByProfileSecret(profileSecret)
                console.log(`Added contact: ${formatContact(contact)}`)
                return
            }
            case 'profile': {
                const positionalSecret = parsed.positionals[0]
                const profileSecret = positionalSecret ?? requireStringOption(parsed.options, 'profile-secret', 'MURMUR_PROFILE_SECRET')
                const profileSecretBytes = decodeBase64(profileSecret, 'base64url')
                const profilePublicKey = encodeBase64(publicKeyFromPrivate(profileSecretBytes))
                const api = new MurmurApi(apiBaseUrl)
                const serverProfile = await api.getPublicProfile(profilePublicKey)
                const profile = decryptProfile(serverProfile.encryptedProfile, profileSecretBytes)
                console.log(`Identity key: ${formatIdentityKey(serverProfile.id)}`)
                console.log(JSON.stringify(profile, null, 2))
                return
            }
            case 'sync': {
                await requireInitialized(getEngine())
                const received: Array<{ contact: Contact; message: StoredMessage }> = []
                const markRead = new Set<string>()
                const unsubscribe = getEngine().on(event => {
                    if (event.type === 'message') {
                        received.push({ contact: event.contact, message: event.message })
                        markRead.add(event.contact.identityKey)
                    }
                    if (event.type === 'error') {
                        console.error(event.error)
                    }
                })

                await getEngine().sync()
                unsubscribe()

                if (received.length === 0) {
                    console.log('No new messages.')
                    return
                }

                for (const { contact, message } of received) {
                    printMessageLine(formatContact(contact), message)
                }

                for (const identityKey of markRead) {
                    getEngine().markAsRead(identityKey)
                }
                return
            }
            case 'messages': {
                await requireInitialized(getEngine())
                const peer = normalizeIdentityKey(requireStringOption(parsed.options, 'with', 'MURMUR_WITH'))
                const limit = readNumberOption(parsed.options, 'limit', 'MURMUR_LIMIT') ?? 20
                if (limit <= 0) {
                    throw new Error('Limit must be a positive number.')
                }

                const contacts = getEngine().getContacts()
                const contact = contacts.find(item => item.identityKey === peer)
                const label = contact ? formatContact(contact) : formatIdentityKey(peer)
                const messages = getEngine().getMessages(peer, limit)

                if (messages.length === 0) {
                    console.log(`No messages for ${label}.`)
                    return
                }

                const resolvedLabel = contact ? formatContact(contact) : formatIdentityKey(peer)
                console.log(`Last ${messages.length} messages for ${resolvedLabel}:`)
                for (const message of messages) {
                    printMessageLine(resolvedLabel, message)
                }

                getEngine().markAsRead(peer)
                return
            }
            default:
                throw new Error(`Unknown command: ${parsed.command}`)
        }
    } finally {
        if (engine) {
            engine.close()
        }
    }
}

run().catch(error => {
    const message = error instanceof Error ? error.message : String(error)
    console.error(message)
    process.exit(1)
})
