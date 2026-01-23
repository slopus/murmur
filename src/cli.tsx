#!/usr/bin/env node
/**
 * Murmur CLI Entry Point.
 *
 * Launches the full-screen TUI application for encrypted messaging.
 *
 * Usage:
 *   murmur [--local]
 *
 * Options:
 *   --local    Use .murmur in current directory instead of ~/.murmur
 */

import React from 'react'
import { render } from 'ink'
import { App } from './ui/App.js'
import { MurmurEngine } from './engine/engine.js'
import { getDbPath } from './storage/database.js'

/**
 * Parse command line arguments.
 */
function parseArgs(): { local: boolean } {
    const args = process.argv.slice(2)
    return {
        local: args.includes('--local')
    }
}

/**
 * Main entry point.
 */
async function main() {
    // Parse command line arguments
    const { local } = parseArgs()

    // Create engine instance with appropriate database path
    const dbPath = getDbPath(local)
    const engine = new MurmurEngine(dbPath)

    // Render the app with ink's fullScreen mode
    const { waitUntilExit } = render(
        <App engine={engine} />,
        {
            exitOnCtrlC: true,
            fullScreen: true
        }
    )

    // Wait for exit
    try {
        await waitUntilExit()
    } finally {
        engine.close()
    }
}

// Run the app
main().catch(error => {
    console.error('Fatal error:', error)
    process.exit(1)
})
