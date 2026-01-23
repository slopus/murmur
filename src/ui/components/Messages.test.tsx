/**
 * Tests for Messages components.
 */

import React from 'react'
import { describe, it, expect } from 'vitest'
import { render } from 'ink-testing-library'
import { MessageBubble, MessageList } from './Messages.js'
import type { StoredMessage } from '../../storage/types.js'

describe('MessageBubble', () => {
    it('should render outgoing message', () => {
        const message: StoredMessage = {
            id: 'msg-1',
            conversationId: 'peer-1',
            isOutgoing: true,
            text: 'Hello there!',
            createdAt: Date.now(),
            read: true
        }

        const { lastFrame } = render(<MessageBubble message={message} />)
        const output = lastFrame()

        expect(output).toContain('Hello there!')
    })

    it('should render incoming message', () => {
        const message: StoredMessage = {
            id: 'msg-2',
            conversationId: 'peer-1',
            isOutgoing: false,
            text: 'Hi back!',
            createdAt: Date.now(),
            read: false
        }

        const { lastFrame } = render(<MessageBubble message={message} />)
        const output = lastFrame()

        expect(output).toContain('Hi back!')
    })

    it('should wrap long messages', () => {
        const longText = 'This is a very long message that should wrap to multiple lines when displayed in the terminal'
        const message: StoredMessage = {
            id: 'msg-3',
            conversationId: 'peer-1',
            isOutgoing: true,
            text: longText,
            createdAt: Date.now(),
            read: true
        }

        const { lastFrame } = render(<MessageBubble message={message} maxWidth={30} />)
        const output = lastFrame()

        // Should contain parts of the message
        expect(output).toContain('This is a')
    })
})

describe('MessageList', () => {
    it('should show placeholder when empty', () => {
        const { lastFrame } = render(<MessageList messages={[]} />)
        const output = lastFrame()

        expect(output).toContain('No messages yet')
    })

    it('should render messages', () => {
        const messages: StoredMessage[] = [
            {
                id: 'msg-1',
                conversationId: 'peer-1',
                isOutgoing: true,
                text: 'First message',
                createdAt: 1000,
                read: true
            },
            {
                id: 'msg-2',
                conversationId: 'peer-1',
                isOutgoing: false,
                text: 'Second message',
                createdAt: 2000,
                read: true
            }
        ]

        const { lastFrame } = render(<MessageList messages={messages} />)
        const output = lastFrame()

        expect(output).toContain('First message')
        expect(output).toContain('Second message')
    })
})
