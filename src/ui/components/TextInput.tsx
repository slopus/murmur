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
}

/**
 * Text input display component.
 * Shows value with cursor indicator.
 */
export function TextInput({
    value,
    cursor,
    placeholder = '',
    focused = true
}: TextInputProps) {
    if (!focused) {
        return (
            <Text color="gray">
                {value || placeholder}
            </Text>
        )
    }

    if (value.length === 0) {
        return (
            <Text>
                <Text backgroundColor="white" color="black"> </Text>
                <Text color="gray">{placeholder}</Text>
            </Text>
        )
    }

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
