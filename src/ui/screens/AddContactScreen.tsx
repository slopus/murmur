/**
 * Add contact screen.
 *
 * Allows entering a contact's identity key to add them.
 */

import React from 'react'
import { Box, Text, useInput } from 'ink'
import { BorderBox } from '../components/Box.js'
import { TextInput } from '../components/TextInput.js'
import { useInput as useTextInput } from '../hooks/useInput.js'
import type { Screen } from '../hooks/useApp.js'

export interface AddContactScreenProps {
    onAddContact: (identityKey: string) => void
    onNavigate: (screen: Screen) => void
}

/**
 * Add contact screen component.
 */
export function AddContactScreen({
    onAddContact,
    onNavigate
}: AddContactScreenProps) {
    const [identityKeyInput, identityKeyActions] = useTextInput('')

    useInput((input, key) => {
        // Escape to go back
        if (key.escape) {
            onNavigate({ type: 'chat_list' })
            return
        }

        // Enter to submit
        if (key.return && identityKeyInput.value.trim()) {
            onAddContact(identityKeyInput.value.trim())
            return
        }

        // Handle text input
        identityKeyActions.handleKey(
            key.backspace || key.delete ? 'backspace' :
            key.leftArrow ? 'left' :
            key.rightArrow ? 'right' :
            input,
            key.ctrl,
            key.meta
        )
    })

    return (
        <Box
            flexDirection="column"
            alignItems="center"
            justifyContent="center"
            width="100%"
            height="100%"
        >
            <Text bold color="cyan">Add Contact</Text>

            <Box marginTop={2}>
                <Text color="gray">
                    Enter the contact's identity key to add them to your contacts.
                </Text>
            </Box>

            <Box marginTop={2} width={60}>
                <BorderBox title="Identity Key" focused>
                    <Box paddingX={1}>
                        <TextInput
                            value={identityKeyInput.value}
                            cursor={identityKeyInput.cursor}
                            placeholder="Paste identity key here..."
                            focused
                        />
                    </Box>
                </BorderBox>
            </Box>

            <Box marginTop={2}>
                <Text color="gray">
                    Press <Text color="white">Enter</Text> to add,{' '}
                    <Text color="white">Esc</Text> to cancel
                </Text>
            </Box>
        </Box>
    )
}
