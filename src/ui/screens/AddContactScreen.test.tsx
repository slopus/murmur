/**
 * Tests for AddContactScreen component.
 */

import React from 'react'
import { describe, it, expect, vi } from 'vitest'
import { render } from 'ink-testing-library'
import { AddContactScreen } from './AddContactScreen.js'

describe('AddContactScreen', () => {
    it('should render title', () => {
        const onAddContact = vi.fn()
        const onNavigate = vi.fn()

        const { lastFrame } = render(
            <AddContactScreen onAddContact={onAddContact} onNavigate={onNavigate} />
        )
        const output = lastFrame()

        expect(output).toContain('Add Contact')
    })

    it('should show identity key input', () => {
        const onAddContact = vi.fn()
        const onNavigate = vi.fn()

        const { lastFrame } = render(
            <AddContactScreen onAddContact={onAddContact} onNavigate={onNavigate} />
        )
        const output = lastFrame()

        expect(output).toContain('Identity Key')
    })

    it('should show instructions', () => {
        const onAddContact = vi.fn()
        const onNavigate = vi.fn()

        const { lastFrame } = render(
            <AddContactScreen onAddContact={onAddContact} onNavigate={onNavigate} />
        )
        const output = lastFrame()

        expect(output).toContain('Enter')
        expect(output).toContain('Esc')
    })
})
