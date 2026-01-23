/**
 * Message display components.
 *
 * Shows conversation messages with proper formatting.
 */

import React from 'react'
import { Box, Text } from 'ink'
import type { StoredMessage } from '../../storage/types.js'

/**
 * Format a timestamp for display.
 */
function formatTime(timestamp: number): string {
    const date = new Date(timestamp)
    const now = new Date()
    const isToday = date.toDateString() === now.toDateString()

    if (isToday) {
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    }

    return date.toLocaleDateString([], { month: 'short', day: 'numeric' })
}

/**
 * Single message bubble.
 */
export function MessageBubble({
    message,
    maxWidth = 60
}: {
    message: StoredMessage
    maxWidth?: number
}) {
    const time = formatTime(message.createdAt)
    const align = message.isOutgoing ? 'flex-end' : 'flex-start'
    const color = message.isOutgoing ? 'cyan' : 'green'

    // Word wrap the message text
    const lines: string[] = []
    let currentLine = ''
    const words = message.text.split(' ')

    for (const word of words) {
        if (currentLine.length + word.length + 1 > maxWidth) {
            if (currentLine) lines.push(currentLine)
            currentLine = word
        } else {
            currentLine = currentLine ? `${currentLine} ${word}` : word
        }
    }
    if (currentLine) lines.push(currentLine)

    return (
        <Box flexDirection="column" alignItems={align} marginY={0}>
            <Box flexDirection="column">
                {lines.map((line, i) => (
                    <Text key={i} color={color}>
                        {message.isOutgoing ? '' : '  '}{line}
                    </Text>
                ))}
                <Text color="gray" dimColor>
                    {message.isOutgoing ? '' : '  '}{time}
                </Text>
            </Box>
        </Box>
    )
}

/**
 * Message list component.
 */
export function MessageList({
    messages,
    maxVisible = 15,
    scrollOffset = 0
}: {
    messages: StoredMessage[]
    maxVisible?: number
    scrollOffset?: number
}) {
    if (messages.length === 0) {
        return (
            <Box justifyContent="center" alignItems="center" flexGrow={1}>
                <Text color="gray">No messages yet. Start the conversation!</Text>
            </Box>
        )
    }

    // Show most recent messages, with scrolling
    const start = Math.max(0, messages.length - maxVisible - scrollOffset)
    const end = messages.length - scrollOffset
    const visibleMessages = messages.slice(start, end)

    return (
        <Box flexDirection="column" paddingX={1}>
            {start > 0 && (
                <Text color="gray">↑ {start} older messages</Text>
            )}

            {visibleMessages.map(message => (
                <MessageBubble key={message.id} message={message} />
            ))}

            {scrollOffset > 0 && (
                <Text color="gray">↓ {scrollOffset} newer messages</Text>
            )}
        </Box>
    )
}

/**
 * Hook for message list scrolling.
 */
export function useMessageScroll(messageCount: number) {
    const [scrollOffset, setScrollOffset] = React.useState(0)

    const scroll = React.useCallback((direction: 'up' | 'down') => {
        setScrollOffset(prev => {
            if (direction === 'up') {
                return Math.min(prev + 3, Math.max(0, messageCount - 5))
            } else {
                return Math.max(0, prev - 3)
            }
        })
    }, [messageCount])

    const scrollToBottom = React.useCallback(() => {
        setScrollOffset(0)
    }, [])

    // Reset scroll when messages change significantly
    React.useEffect(() => {
        setScrollOffset(0)
    }, [messageCount])

    return { scrollOffset, scroll, scrollToBottom }
}
