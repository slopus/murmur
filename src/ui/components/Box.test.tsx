/**
 * Tests for Box layout components.
 */

import React from 'react'
import { describe, it, expect } from 'vitest'
import { render } from 'ink-testing-library'
import { Text } from 'ink'
import { BorderBox, TwoColumnLayout } from './Box.js'

describe('BorderBox', () => {
    it('should render children', () => {
        const { lastFrame } = render(
            <BorderBox>
                <Text>Content</Text>
            </BorderBox>
        )
        const output = lastFrame()

        expect(output).toContain('Content')
    })

    it('should render title', () => {
        const { lastFrame } = render(
            <BorderBox title="Test Title">
                <Text>Content</Text>
            </BorderBox>
        )
        const output = lastFrame()

        expect(output).toContain('Test Title')
    })

    it('should render with focused style', () => {
        const { lastFrame: frame1 } = render(
            <BorderBox focused={true}>
                <Text>Content</Text>
            </BorderBox>
        )

        const { lastFrame: frame2 } = render(
            <BorderBox focused={false}>
                <Text>Content</Text>
            </BorderBox>
        )

        // Both should render, focused might have different styling
        expect(frame1()).toContain('Content')
        expect(frame2()).toContain('Content')
    })
})

describe('TwoColumnLayout', () => {
    it('should render sidebar and main content', () => {
        const { lastFrame } = render(
            <TwoColumnLayout
                sidebar={<Text>Sidebar</Text>}
                main={<Text>Main</Text>}
            />
        )
        const output = lastFrame()

        expect(output).toContain('Sidebar')
        expect(output).toContain('Main')
    })
})
