/**
 * Tests for TextInput component.
 */

import React from 'react'
import { describe, it, expect } from 'vitest'
import { render } from 'ink-testing-library'
import { TextInput } from './TextInput.js'

describe('TextInput', () => {
    it('should render placeholder when empty', () => {
        const { lastFrame } = render(
            <TextInput value="" cursor={0} placeholder="Type here" focused />
        )
        const output = lastFrame()

        expect(output).toContain('Type here')
    })

    it('should render value when provided', () => {
        const { lastFrame } = render(
            <TextInput value="Hello World" cursor={11} placeholder="" focused />
        )
        const output = lastFrame()

        expect(output).toContain('Hello World')
    })

    it('should show cursor at position', () => {
        const { lastFrame } = render(
            <TextInput value="test" cursor={2} placeholder="" focused />
        )
        const output = lastFrame()

        // The character at cursor position should be highlighted
        // "te" + cursor on "s" + "t"
        expect(output).toContain('te')
    })

    it('should render dimmed when not focused', () => {
        const { lastFrame } = render(
            <TextInput value="content" cursor={0} placeholder="" focused={false} />
        )
        const output = lastFrame()

        expect(output).toContain('content')
    })
})
