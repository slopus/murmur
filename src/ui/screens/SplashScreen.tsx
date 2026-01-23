/**
 * Splash screen shown during app loading.
 */

import React from 'react'
import { Box, Text } from 'ink'
import { Spinner } from '../components/Spinner.js'

const LOGO = `
╔══════════════════════════════════════╗
║                                      ║
║    ███╗   ███╗██╗   ██╗██████╗       ║
║    ████╗ ████║██║   ██║██╔══██╗      ║
║    ██╔████╔██║██║   ██║██████╔╝      ║
║    ██║╚██╔╝██║██║   ██║██╔══██╗      ║
║    ██║ ╚═╝ ██║╚██████╔╝██║  ██║      ║
║    ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝      ║
║                                      ║
║    Encrypted Messenger for Agents    ║
║                                      ║
╚══════════════════════════════════════╝
`.trim()

/**
 * Loading splash screen.
 */
export function SplashScreen() {
    return (
        <Box
            flexDirection="column"
            alignItems="center"
            justifyContent="center"
            width="100%"
            height="100%"
        >
            <Text bold color="cyan">
                {LOGO}
            </Text>
            <Box marginTop={2}>
                <Spinner label="Loading..." />
            </Box>
        </Box>
    )
}
