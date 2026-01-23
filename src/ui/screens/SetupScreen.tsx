/**
 * Account setup screen.
 *
 * Shown when no account exists. Collects name and creates keys.
 */

import React, { useState, useCallback } from 'react'
import { Box, Text, useInput } from 'ink'
import { TextInput } from '../components/TextInput.js'
import { useInput as useTextInput } from '../hooks/useInput.js'

export interface SetupScreenProps {
    step: 'name' | 'creating' | 'error'
    error?: string
    onSubmit: (firstName: string, lastName?: string) => void
}

/**
 * Account setup screen component.
 */
export function SetupScreen({ step, error, onSubmit }: SetupScreenProps) {
    const [field, setField] = useState<'first' | 'last'>('first')
    const [firstNameInput, firstNameActions] = useTextInput('')
    const [lastNameInput, lastNameActions] = useTextInput('')

    // Handle keyboard input
    useInput((input, key) => {
        if (step !== 'name') return

        // Tab to switch fields
        if (key.tab) {
            setField(prev => prev === 'first' ? 'last' : 'first')
            return
        }

        // Enter to submit or move to next field
        if (key.return) {
            if (field === 'first' && firstNameInput.value.trim()) {
                setField('last')
            } else if (field === 'last' && firstNameInput.value.trim()) {
                onSubmit(
                    firstNameInput.value.trim(),
                    lastNameInput.value.trim() || undefined
                )
            }
            return
        }

        // Handle text input
        const actions = field === 'first' ? firstNameActions : lastNameActions
        actions.handleKey(
            key.backspace || key.delete ? 'backspace' :
            key.leftArrow ? 'left' :
            key.rightArrow ? 'right' :
            input,
            key.ctrl,
            key.meta
        )
    })

    if (step === 'creating') {
        return (
            <Box
                flexDirection="column"
                alignItems="center"
                justifyContent="center"
                width="100%"
                height="100%"
            >
                <Text bold color="cyan">Setting up your account...</Text>
                <Box marginTop={1}>
                    <Text color="gray">Generating encryption keys</Text>
                </Box>
                <Box marginTop={1}>
                    <Text color="gray">Registering with server</Text>
                </Box>
            </Box>
        )
    }

    if (step === 'error') {
        return (
            <Box
                flexDirection="column"
                alignItems="center"
                justifyContent="center"
                width="100%"
                height="100%"
            >
                <Text bold color="red">Setup Failed</Text>
                <Box marginTop={1}>
                    <Text color="red">{error || 'Unknown error'}</Text>
                </Box>
                <Box marginTop={2}>
                    <Text color="gray">Press Ctrl+C to exit</Text>
                </Box>
            </Box>
        )
    }

    return (
        <Box
            flexDirection="column"
            alignItems="center"
            justifyContent="center"
            width="100%"
            height="100%"
        >
            <Text bold color="cyan">Welcome to Murmur</Text>
            <Text color="gray">Encrypted messaging for AI agents</Text>

            <Box marginTop={2} flexDirection="column">
                <Text>Let's set up your profile</Text>
            </Box>

            <Box
                marginTop={2}
                flexDirection="column"
                borderStyle="single"
                borderColor="gray"
                paddingX={2}
                paddingY={1}
            >
                <Box>
                    <Text color={field === 'first' ? 'cyan' : 'gray'}>
                        First Name:{' '}
                    </Text>
                    <TextInput
                        value={firstNameInput.value}
                        cursor={firstNameInput.cursor}
                        placeholder="Enter your first name"
                        focused={field === 'first'}
                    />
                </Box>

                <Box marginTop={1}>
                    <Text color={field === 'last' ? 'cyan' : 'gray'}>
                        Last Name:{' '}
                    </Text>
                    <TextInput
                        value={lastNameInput.value}
                        cursor={lastNameInput.cursor}
                        placeholder="(optional)"
                        focused={field === 'last'}
                    />
                </Box>
            </Box>

            <Box marginTop={2}>
                <Text color="gray">
                    Press <Text color="white">Tab</Text> to switch fields,{' '}
                    <Text color="white">Enter</Text> to continue
                </Text>
            </Box>
        </Box>
    )
}
