#!/usr/bin/env node

/**
 * Murmur CLI entry point.
 *
 * This is the executable entry point for the murmur command.
 * It handles Node.js flags and imports the main module.
 */

import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

// Check if we have the required Node flags
const hasNoWarnings = process.execArgv.includes('--no-warnings')
const hasNoDeprecation = process.execArgv.includes('--no-deprecation')

if (!hasNoWarnings || !hasNoDeprecation) {
    // Re-exec with proper flags
    const entrypoint = resolve(__dirname, 'murmur.mjs')
    try {
        execFileSync(process.execPath, [
            '--no-warnings',
            '--no-deprecation',
            entrypoint,
            ...process.argv.slice(2)
        ], {
            stdio: 'inherit',
            env: process.env
        })
    } catch (error) {
        // execFileSync throws on non-zero exit
        if (error && typeof error === 'object' && 'status' in error) {
            process.exit(error.status ?? 1)
        }
        process.exit(1)
    }
} else {
    // We have the flags, run the main module
    import('../dist/index.mjs')
}
