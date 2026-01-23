/**
 * Text input component for the TUI.
 *
 * Displays a text input field with cursor.
 */

import React from 'react'
import { Box, Text } from 'ink'

export interface TextInputProps {
    value: string
    cursor: number
    placeholder?: string
    focused?: boolean
    width?: number
}

/**
 * Text input display component.
 * Shows value with cursor indicator.
 * Always renders exactly one line with fixed width.
 */
export function TextInput({
    value,
    cursor,
    placeholder = '',
    focused = true,
    width
}: TextInputProps) {
    // Calculate the display width
    const displayWidth = width || 20

    // Always render inside a fixed-width box to prevent layout shifts
    const renderContent = () => {
        if (!focused) {
            // Unfocused: show value or placeholder
            const display = value || placeholder
            return <Text color="gray">{display}</Text>
        }

        if (value.length === 0) {
            // Empty: show cursor then placeholder
            return (
                <Text>
                    <Text backgroundColor="white" color="black"> </Text>
                    <Text color="gray">{placeholder}</Text>
                </Text>
            )
        }

        // Has value: show text with cursor
        const beforeCursor = value.slice(0, cursor)
        const atCursor = value[cursor] || ' '
        const afterCursor = value.slice(cursor + 1)

        return (
            <Text>
                {beforeCursor}
                <Text backgroundColor="white" color="black">{atCursor}</Text>
                {afterCursor}
            </Text>
        )
    }

    return (
        <Box width={displayWidth} height={1} overflow="hidden">
            {renderContent()}
        </Box>
    )
}
