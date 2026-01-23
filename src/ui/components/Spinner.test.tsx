/**
 * Tests for Spinner component.
 */

import React from 'react'
import { describe, it, expect } from 'vitest'
import { render } from 'ink-testing-library'
import { Spinner } from './Spinner.js'

describe('Spinner', () => {
    it('should render a spinner character', () => {
        const { lastFrame } = render(<Spinner />)
        const output = lastFrame()

        // Should contain one of the spinner frames
        expect(output).toMatch(/[⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏]/)
    })

    it('should render with a label', () => {
        const { lastFrame } = render(<Spinner label="Loading..." />)
        const output = lastFrame()

        expect(output).toContain('Loading...')
    })
})
