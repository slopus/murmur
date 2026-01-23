/**
 * Tests for SetupScreen component.
 */

import React from 'react'
import { describe, it, expect, vi } from 'vitest'
import { render } from 'ink-testing-library'
import { SetupScreen } from './SetupScreen.js'

describe('SetupScreen', () => {
    it('should render name input step', () => {
        const onSubmit = vi.fn()
        const { lastFrame } = render(
            <SetupScreen step="name" onSubmit={onSubmit} />
        )
        const output = lastFrame()

        expect(output).toContain('Welcome to Murmur')
        expect(output).toContain('First Name')
        expect(output).toContain('Last Name')
    })

    it('should render creating step', () => {
        const onSubmit = vi.fn()
        const { lastFrame } = render(
            <SetupScreen step="creating" onSubmit={onSubmit} />
        )
        const output = lastFrame()

        expect(output).toContain('Setting up your account')
        expect(output).toContain('Generating encryption keys')
    })

    it('should render error step', () => {
        const onSubmit = vi.fn()
        const { lastFrame } = render(
            <SetupScreen step="error" error="Network error" onSubmit={onSubmit} />
        )
        const output = lastFrame()

        expect(output).toContain('Setup Failed')
        expect(output).toContain('Network error')
    })

    it('should show instructions', () => {
        const onSubmit = vi.fn()
        const { lastFrame } = render(
            <SetupScreen step="name" onSubmit={onSubmit} />
        )
        const output = lastFrame()

        expect(output).toContain('Tab')
        expect(output).toContain('Enter')
    })
})
