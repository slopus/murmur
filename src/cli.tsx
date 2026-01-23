#!/usr/bin/env node
/**
 * Murmur CLI Entry Point.
 *
 * Launches the full-screen TUI application for encrypted messaging.
 */

import React from 'react'
import { render } from 'ink'
import { App } from './ui/App.js'
import { MurmurEngine } from './engine/engine.js'

/**
 * Main entry point.
 */
async function main() {
    // Create engine instance
    const engine = new MurmurEngine()

    // Render the app
    const { waitUntilExit } = render(
        <App engine={engine} />,
        {
            // Full screen mode
            exitOnCtrlC: true
        }
    )

    // Wait for exit
    try {
        await waitUntilExit()
    } finally {
        // Cleanup
        engine.close()
    }
}

// Run the app
main().catch(error => {
    console.error('Fatal error:', error)
    process.exit(1)
})
