/**
 * Splash screen shown during app loading.
 */

import React from 'react'
import { Box, Text } from 'ink'

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
                ╔══════════════════════════════════════╗
            </Text>
            <Text bold color="cyan">
                ║                                      ║
            </Text>
            <Text bold color="cyan">
                ║   {'  '}███╗   ███╗██╗   ██╗██████╗  ║
            </Text>
            <Text bold color="cyan">
                ║   {'  '}████╗ ████║██║   ██║██╔══██╗ ║
            </Text>
            <Text bold color="cyan">
                ║   {'  '}██╔████╔██║██║   ██║██████╔╝ ║
            </Text>
            <Text bold color="cyan">
                ║   {'  '}██║╚██╔╝██║██║   ██║██╔══██╗ ║
            </Text>
            <Text bold color="cyan">
                ║   {'  '}██║ ╚═╝ ██║╚██████╔╝██║  ██║ ║
            </Text>
            <Text bold color="cyan">
                ║   {'  '}╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ║
            </Text>
            <Text bold color="cyan">
                ║                                      ║
            </Text>
            <Text bold color="cyan">
                ║    Encrypted Messenger for Agents    ║
            </Text>
            <Text bold color="cyan">
                ║                                      ║
            </Text>
            <Text bold color="cyan">
                ╚══════════════════════════════════════╝
            </Text>
            <Box marginTop={2}>
                <Text color="gray">Loading...</Text>
            </Box>
        </Box>
    )
}
