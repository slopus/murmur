/**
 * Tests for List component rendering.
 */

import React from 'react'
import { describe, it, expect } from 'vitest'
import { render } from 'ink-testing-library'
import { List, type ListItem } from './List.js'

describe('List component', () => {
    it('should show "No items" when empty', () => {
        const { lastFrame } = render(
            <List items={[]} selectedIndex={0} />
        )
        const output = lastFrame()

        expect(output).toContain('No items')
    })

    it('should render items', () => {
        const items: ListItem[] = [
            { key: '1', label: 'Item One' },
            { key: '2', label: 'Item Two' },
            { key: '3', label: 'Item Three' }
        ]

        const { lastFrame } = render(
            <List items={items} selectedIndex={0} focused />
        )
        const output = lastFrame()

        expect(output).toContain('Item One')
        expect(output).toContain('Item Two')
        expect(output).toContain('Item Three')
    })

    it('should show selection indicator', () => {
        const items: ListItem[] = [
            { key: '1', label: 'First' },
            { key: '2', label: 'Second' }
        ]

        const { lastFrame } = render(
            <List items={items} selectedIndex={1} focused />
        )
        const output = lastFrame()

        // Selected item should have indicator
        expect(output).toContain('▸')
    })

    it('should render sublabels', () => {
        const items: ListItem[] = [
            { key: '1', label: 'Contact', sublabel: 'Last message' }
        ]

        const { lastFrame } = render(
            <List items={items} selectedIndex={0} focused />
        )
        const output = lastFrame()

        expect(output).toContain('Contact')
        expect(output).toContain('Last message')
    })

    it('should render badges', () => {
        const items: ListItem[] = [
            { key: '1', label: 'Chat', badge: 5 }
        ]

        const { lastFrame } = render(
            <List items={items} selectedIndex={0} focused />
        )
        const output = lastFrame()

        expect(output).toContain('Chat')
        expect(output).toContain('(5)')
    })

    it('should not render zero badges', () => {
        const items: ListItem[] = [
            { key: '1', label: 'Chat', badge: 0 }
        ]

        const { lastFrame } = render(
            <List items={items} selectedIndex={0} focused />
        )
        const output = lastFrame()

        expect(output).toContain('Chat')
        expect(output).not.toContain('(0)')
    })

    it('should show scroll indicators when needed', () => {
        const items: ListItem[] = Array.from({ length: 20 }, (_, i) => ({
            key: String(i),
            label: `Item ${i}`
        }))

        const { lastFrame } = render(
            <List items={items} selectedIndex={5} scrollOffset={3} maxVisible={5} focused />
        )
        const output = lastFrame()

        // Should show scroll indicators
        expect(output).toContain('more')
    })
})
