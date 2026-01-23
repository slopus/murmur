/**
 * Tests for SplashScreen component.
 */

import React from 'react'
import { describe, it, expect } from 'vitest'
import { render } from 'ink-testing-library'
import { SplashScreen } from './SplashScreen.js'

describe('SplashScreen', () => {
    it('should render the logo', () => {
        const { lastFrame } = render(<SplashScreen />)
        const output = lastFrame()

        expect(output).toContain('Encrypted Messenger for Agents')
        expect(output).toContain('Loading...')
    })

    it('should contain the MUR text', () => {
        const { lastFrame } = render(<SplashScreen />)
        const output = lastFrame()

        // Check for parts of the ASCII art
        expect(output).toContain('███')
    })
})
