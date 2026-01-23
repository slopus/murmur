/**
 * Tests for ChatScreen component.
 */

import React from 'react'
import { describe, it, expect, vi } from 'vitest'
import { render } from 'ink-testing-library'
import { ChatScreen } from './ChatScreen.js'
import type { Account, StoredMessage } from '../../storage/types.js'
import type { Conversation } from '../../engine/engine.js'

describe('ChatScreen', () => {
    const mockAccount: Account = {
        identityKey: 'test-identity-key',
        profilePublicKey: 'test-profile-public-key',
        profileSecretKey: 'test-profile-secret-key',
        encryptedProfile: 'test-encrypted-profile',
        firstName: 'Alice',
        lastName: 'Agent',
        createdAt: Date.now()
    }

    const mockConversations: Conversation[] = [
        {
            contact: {
                identityKey: 'bob-identity-key',
                profilePublicKey: 'bob-profile-key',
                firstName: 'Bob',
                addedAt: Date.now(),
                updatedAt: Date.now()
            },
            messages: [],
            unreadCount: 2,
            lastMessage: {
                id: 'msg-1',
                conversationId: 'bob-identity-key',
                isOutgoing: false,
                text: 'Hello there',
                createdAt: Date.now(),
                read: false
            }
        },
        {
            contact: {
                identityKey: 'carol-identity-key',
                profilePublicKey: 'carol-profile-key',
                firstName: 'Carol',
                lastName: 'Smith',
                addedAt: Date.now(),
                updatedAt: Date.now()
            },
            messages: [],
            unreadCount: 0
        }
    ]

    const mockMessages: StoredMessage[] = [
        {
            id: 'msg-1',
            conversationId: 'bob-identity-key',
            isOutgoing: false,
            text: 'Hey Alice!',
            createdAt: Date.now() - 60000,
            read: true
        },
        {
            id: 'msg-2',
            conversationId: 'bob-identity-key',
            isOutgoing: true,
            text: 'Hi Bob!',
            createdAt: Date.now(),
            read: true
        }
    ]

    it('should render header with account name', () => {
        const onNavigate = vi.fn()
        const onSendMessage = vi.fn()

        const { lastFrame } = render(
            <ChatScreen
                account={mockAccount}
                conversations={mockConversations}
                selectedConversation={null}
                messages={[]}
                onNavigate={onNavigate}
                onSendMessage={onSendMessage}
            />
        )
        const output = lastFrame()

        expect(output).toContain('Murmur')
        expect(output).toContain('Alice')
    })

    it('should show contacts list', () => {
        const onNavigate = vi.fn()
        const onSendMessage = vi.fn()

        const { lastFrame } = render(
            <ChatScreen
                account={mockAccount}
                conversations={mockConversations}
                selectedConversation={null}
                messages={[]}
                onNavigate={onNavigate}
                onSendMessage={onSendMessage}
            />
        )
        const output = lastFrame()

        expect(output).toContain('Contacts')
        expect(output).toContain('Bob')
        expect(output).toContain('Carol')
    })

    it('should show empty contacts message', () => {
        const onNavigate = vi.fn()
        const onSendMessage = vi.fn()

        const { lastFrame } = render(
            <ChatScreen
                account={mockAccount}
                conversations={[]}
                selectedConversation={null}
                messages={[]}
                onNavigate={onNavigate}
                onSendMessage={onSendMessage}
            />
        )
        const output = lastFrame()

        expect(output).toContain('No contacts yet')
        expect(output).toContain('Ctrl+N')
    })

    it('should show selected conversation messages', () => {
        const onNavigate = vi.fn()
        const onSendMessage = vi.fn()

        const { lastFrame } = render(
            <ChatScreen
                account={mockAccount}
                conversations={mockConversations}
                selectedConversation={mockConversations[0]}
                messages={mockMessages}
                onNavigate={onNavigate}
                onSendMessage={onSendMessage}
            />
        )
        const output = lastFrame()

        // Should show the conversation title
        expect(output).toContain('Bob')
        // Should show messages
        expect(output).toContain('Hey Alice!')
        expect(output).toContain('Hi Bob!')
    })

    it('should show placeholder when no conversation selected', () => {
        const onNavigate = vi.fn()
        const onSendMessage = vi.fn()

        const { lastFrame } = render(
            <ChatScreen
                account={mockAccount}
                conversations={mockConversations}
                selectedConversation={null}
                messages={[]}
                onNavigate={onNavigate}
                onSendMessage={onSendMessage}
            />
        )
        const output = lastFrame()

        expect(output).toContain('Select a contact')
    })

    it('should show message input when conversation is selected', () => {
        const onNavigate = vi.fn()
        const onSendMessage = vi.fn()

        const { lastFrame } = render(
            <ChatScreen
                account={mockAccount}
                conversations={mockConversations}
                selectedConversation={mockConversations[0]}
                messages={mockMessages}
                onNavigate={onNavigate}
                onSendMessage={onSendMessage}
            />
        )
        const output = lastFrame()

        expect(output).toContain('Message')
        expect(output).toContain('Type a message')
    })

    it('should show unread badges', () => {
        const onNavigate = vi.fn()
        const onSendMessage = vi.fn()

        const { lastFrame } = render(
            <ChatScreen
                account={mockAccount}
                conversations={mockConversations}
                selectedConversation={null}
                messages={[]}
                onNavigate={onNavigate}
                onSendMessage={onSendMessage}
            />
        )
        const output = lastFrame()

        // Bob has 2 unread messages
        expect(output).toContain('(2)')
    })

    it('should show keyboard shortcuts in header', () => {
        const onNavigate = vi.fn()
        const onSendMessage = vi.fn()

        const { lastFrame } = render(
            <ChatScreen
                account={mockAccount}
                conversations={mockConversations}
                selectedConversation={null}
                messages={[]}
                onNavigate={onNavigate}
                onSendMessage={onSendMessage}
            />
        )
        const output = lastFrame()

        expect(output).toContain('Tab')
        expect(output).toContain('Esc')
        expect(output).toContain('Ctrl+N')
        expect(output).toContain('Ctrl+P')
        expect(output).toContain('Ctrl+C')
    })
})
