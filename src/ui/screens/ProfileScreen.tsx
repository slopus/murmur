/**
 * Profile screen showing the user's identity information.
 *
 * Displays the identity key that can be shared with others.
 */

import React from 'react'
import { Box, Text, useInput } from 'ink'
import { BorderBox } from '../components/Box.js'
import type { Account } from '../../storage/types.js'
import type { Screen } from '../hooks/useApp.js'

export interface ProfileScreenProps {
    account: Account
    onNavigate: (screen: Screen) => void
}

/**
 * Profile screen component.
 */
export function ProfileScreen({
    account,
    onNavigate
}: ProfileScreenProps) {
    useInput((_input, key) => {
        // Escape or any key to go back
        if (key.escape || key.return) {
            onNavigate({ type: 'chat_list' })
        }
    })

    return (
        <Box
            flexDirection="column"
            alignItems="center"
            justifyContent="center"
            width="100%"
            height="100%"
        >
            <Text bold color="cyan">Your Profile</Text>

            <Box marginTop={2} width={70}>
                <BorderBox title="Name">
                    <Box paddingX={1}>
                        <Text color="white">
                            {account.firstName}
                            {account.lastName ? ` ${account.lastName}` : ''}
                        </Text>
                    </Box>
                </BorderBox>
            </Box>

            <Box marginTop={1} width={70}>
                <BorderBox title="Identity Key (share this with contacts)">
                    <Box paddingX={1} flexDirection="column">
                        <Text color="green" wrap="wrap">
                            {account.identityKey}
                        </Text>
                    </Box>
                </BorderBox>
            </Box>

            <Box marginTop={2}>
                <Text color="gray">
                    Share your identity key with others so they can add you as a contact.
                </Text>
            </Box>

            <Box marginTop={1}>
                <Text color="gray">
                    Press <Text color="white">Enter</Text> or{' '}
                    <Text color="white">Esc</Text> to go back
                </Text>
            </Box>
        </Box>
    )
}
