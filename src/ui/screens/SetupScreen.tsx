/**
 * Account setup screen.
 *
 * Shown when no account exists. Collects name and creates keys.
 */

import React, { useState } from 'react'
import { Box, Text, useInput } from 'ink'
import { TextInput } from '../components/TextInput.js'
import { Spinner } from '../components/Spinner.js'
import { useInput as useTextInput } from '../hooks/useInput.js'

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

// Fixed width for form to prevent layout shifts
const FORM_WIDTH = 42
// Fixed width for text inputs (form width minus label and padding)
const INPUT_WIDTH = 24

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
                <Text bold color="cyan">
                    {LOGO}
                </Text>
                <Box marginTop={2}>
                    <Spinner label="Setting up your account..." />
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
                <Text bold color="cyan">
                    {LOGO}
                </Text>
                <Box
                    marginTop={2}
                    borderStyle="round"
                    borderColor="red"
                    paddingX={2}
                    paddingY={1}
                    width={FORM_WIDTH}
                    flexDirection="column"
                    alignItems="center"
                >
                    <Text bold color="red">Setup Failed</Text>
                    <Box marginTop={1}>
                        <Text color="red">{error || 'Unknown error'}</Text>
                    </Box>
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
            <Text bold color="cyan">
                {LOGO}
            </Text>

            <Box
                marginTop={2}
                flexDirection="column"
                borderStyle="single"
                borderColor="gray"
                paddingX={2}
                paddingY={1}
                width={FORM_WIDTH}
            >
                <Box flexDirection="column" alignItems="center" marginBottom={1}>
                    <Text>Create Your Profile</Text>
                </Box>

                <Box height={1}>
                    <Text color={field === 'first' ? 'cyan' : 'gray'}>
                        First Name:{' '}
                    </Text>
                    <TextInput
                        value={firstNameInput.value}
                        cursor={firstNameInput.cursor}
                        placeholder="required"
                        focused={field === 'first'}
                        width={INPUT_WIDTH}
                    />
                </Box>

                <Box height={1} marginTop={1}>
                    <Text color={field === 'last' ? 'cyan' : 'gray'}>
                        Last Name:{' '}
                    </Text>
                    <TextInput
                        value={lastNameInput.value}
                        cursor={lastNameInput.cursor}
                        placeholder="optional"
                        focused={field === 'last'}
                        width={INPUT_WIDTH}
                    />
                </Box>
            </Box>

            <Box marginTop={1}>
                <Text color="gray">
                    <Text color="white">Tab</Text> switch fields · <Text color="white">Enter</Text> continue
                </Text>
            </Box>
        </Box>
    )
}
