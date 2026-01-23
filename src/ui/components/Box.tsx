/**
 * Layout components for the TUI.
 *
 * Provides consistent styling and layout primitives.
 */

import React from 'react'
import { Box as InkBox, Text } from 'ink'

/**
 * Bordered box component.
 */
export function BorderBox({
    children,
    title,
    width,
    height,
    focused = false
}: {
    children: React.ReactNode
    title?: string
    width?: number | string
    height?: number | string
    focused?: boolean
}) {
    const borderColor = focused ? 'cyan' : 'gray'

    return (
        <InkBox
            flexDirection="column"
            width={width}
            height={height}
            borderStyle="single"
            borderColor={borderColor}
        >
            {title && (
                <InkBox marginTop={-1} marginLeft={1}>
                    <Text color={borderColor}> {title} </Text>
                </InkBox>
            )}
            {children}
        </InkBox>
    )
}

/**
 * Full-screen layout with header and content.
 */
export function FullScreen({
    children,
    header
}: {
    children: React.ReactNode
    header?: React.ReactNode
}) {
    return (
        <InkBox flexDirection="column" width="100%" height="100%">
            {header && (
                <InkBox borderStyle="single" borderColor="blue" paddingX={1}>
                    {header}
                </InkBox>
            )}
            <InkBox flexGrow={1} flexDirection="row">
                {children}
            </InkBox>
        </InkBox>
    )
}

/**
 * Two-column layout (sidebar + main).
 */
export function TwoColumnLayout({
    sidebar,
    main,
    sidebarWidth = 30
}: {
    sidebar: React.ReactNode
    main: React.ReactNode
    sidebarWidth?: number
}) {
    return (
        <InkBox flexDirection="row" width="100%" height="100%">
            <InkBox width={sidebarWidth} flexShrink={0}>
                {sidebar}
            </InkBox>
            <InkBox flexGrow={1}>
                {main}
            </InkBox>
        </InkBox>
    )
}
