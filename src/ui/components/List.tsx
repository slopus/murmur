/**
 * List components for the TUI.
 *
 * Provides selectable list with keyboard navigation.
 */

import React from 'react'
import { Box, Text } from 'ink'

export interface ListItem {
    key: string
    label: string
    sublabel?: string
    badge?: string | number
}

export interface ListProps {
    items: ListItem[]
    selectedIndex: number
    focused?: boolean
    maxVisible?: number
    scrollOffset?: number
}

/**
 * Selectable list component.
 */
export function List({
    items,
    selectedIndex,
    focused = true,
    maxVisible = 10,
    scrollOffset = 0
}: ListProps) {
    if (items.length === 0) {
        return (
            <Box paddingX={1}>
                <Text color="gray">No items</Text>
            </Box>
        )
    }

    // Calculate visible range
    const start = scrollOffset
    const end = Math.min(start + maxVisible, items.length)
    const visibleItems = items.slice(start, end)

    return (
        <Box flexDirection="column">
            {start > 0 && (
                <Box paddingX={1}>
                    <Text color="gray">↑ {start} more</Text>
                </Box>
            )}

            {visibleItems.map((item, i) => {
                const actualIndex = start + i
                const isSelected = actualIndex === selectedIndex

                return (
                    <Box key={item.key} paddingX={1}>
                        <Text
                            backgroundColor={isSelected && focused ? 'blue' : undefined}
                            color={isSelected && focused ? 'white' : undefined}
                        >
                            {isSelected ? '▸ ' : '  '}
                            {item.label}
                            {item.sublabel && (
                                <Text color={isSelected && focused ? 'white' : 'gray'}>
                                    {' '}{item.sublabel}
                                </Text>
                            )}
                            {item.badge !== undefined && item.badge !== 0 && (
                                <Text color="yellow"> ({item.badge})</Text>
                            )}
                        </Text>
                    </Box>
                )
            })}

            {end < items.length && (
                <Box paddingX={1}>
                    <Text color="gray">↓ {items.length - end} more</Text>
                </Box>
            )}
        </Box>
    )
}

/**
 * Hook for list navigation.
 */
export function useListNavigation(itemCount: number, maxVisible: number = 10) {
    const [selectedIndex, setSelectedIndex] = React.useState(0)
    const [scrollOffset, setScrollOffset] = React.useState(0)

    const navigate = React.useCallback((direction: 'up' | 'down') => {
        setSelectedIndex(prev => {
            let newIndex = prev

            if (direction === 'up') {
                newIndex = Math.max(0, prev - 1)
            } else {
                newIndex = Math.min(itemCount - 1, prev + 1)
            }

            // Adjust scroll offset
            if (newIndex < scrollOffset) {
                setScrollOffset(newIndex)
            } else if (newIndex >= scrollOffset + maxVisible) {
                setScrollOffset(newIndex - maxVisible + 1)
            }

            return newIndex
        })
    }, [itemCount, maxVisible, scrollOffset])

    const reset = React.useCallback(() => {
        setSelectedIndex(0)
        setScrollOffset(0)
    }, [])

    return {
        selectedIndex,
        scrollOffset,
        navigate,
        reset,
        setSelectedIndex
    }
}
