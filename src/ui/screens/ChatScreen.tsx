/**
 * Main chat screen with contact list and conversation view.
 *
 * Two-panel layout similar to k9s:
 * - Left panel: Contact list
 * - Right panel: Current conversation
 */

import React, { useState, useCallback } from 'react'
import { Box, Text, useInput } from 'ink'
import { BorderBox, TwoColumnLayout } from '../components/Box.js'
import { List, useListNavigation, type ListItem } from '../components/List.js'
import { MessageList, useMessageScroll } from '../components/Messages.js'
import { TextInput } from '../components/TextInput.js'
import { useInput as useTextInput } from '../hooks/useInput.js'
import type { Conversation } from '../../engine/engine.js'
import type { StoredMessage, Account } from '../../storage/types.js'
import type { Screen } from '../hooks/useApp.js'

export interface ChatScreenProps {
    account: Account
    conversations: Conversation[]
    selectedConversation: Conversation | null
    messages: StoredMessage[]
    onNavigate: (screen: Screen) => void
    onSendMessage: (text: string) => void
}

type FocusPanel = 'contacts' | 'messages' | 'input'

/**
 * Main chat screen component.
 */
export function ChatScreen({
    account,
    conversations,
    selectedConversation,
    messages,
    onNavigate,
    onSendMessage
}: ChatScreenProps) {
    const [focusPanel, setFocusPanel] = useState<FocusPanel>('contacts')
    const [messageInput, messageInputActions] = useTextInput('')

    // Contact list navigation
    const contactItems: ListItem[] = conversations.map(conv => ({
        key: conv.contact.identityKey,
        label: conv.contact.firstName + (conv.contact.lastName ? ` ${conv.contact.lastName}` : ''),
        sublabel: conv.lastMessage?.text.slice(0, 20),
        badge: conv.unreadCount
    }))

    const {
        selectedIndex,
        scrollOffset,
        navigate: navigateList
    } = useListNavigation(contactItems.length)

    // Message scrolling
    const { scrollOffset: messageScrollOffset, scroll: scrollMessages } = useMessageScroll(messages.length)

    // Handle keyboard input
    useInput((input, key) => {
        // Global shortcuts
        if (key.escape) {
            if (focusPanel === 'input') {
                setFocusPanel('messages')
            } else if (focusPanel === 'messages') {
                setFocusPanel('contacts')
            } else if (selectedConversation) {
                onNavigate({ type: 'chat_list' })
            }
            return
        }

        // Tab to switch panels
        if (key.tab) {
            if (focusPanel === 'contacts' && selectedConversation) {
                setFocusPanel('messages')
            } else if (focusPanel === 'messages') {
                setFocusPanel('input')
            } else if (focusPanel === 'input') {
                setFocusPanel('contacts')
            }
            return
        }

        // Ctrl+N for new contact
        if (key.ctrl && input === 'n') {
            onNavigate({ type: 'add_contact' })
            return
        }

        // Ctrl+P for profile
        if (key.ctrl && input === 'p') {
            onNavigate({ type: 'profile' })
            return
        }

        // Handle panel-specific input
        switch (focusPanel) {
            case 'contacts':
                if (key.upArrow) {
                    navigateList('up')
                } else if (key.downArrow) {
                    navigateList('down')
                } else if (key.return && contactItems.length > 0) {
                    const selectedContact = conversations[selectedIndex]
                    if (selectedContact) {
                        onNavigate({
                            type: 'conversation',
                            contactId: selectedContact.contact.identityKey
                        })
                        setFocusPanel('input')
                    }
                }
                break

            case 'messages':
                if (key.upArrow) {
                    scrollMessages('up')
                } else if (key.downArrow) {
                    scrollMessages('down')
                } else if (input === 'i' || key.return) {
                    setFocusPanel('input')
                }
                break

            case 'input':
                if (key.return && messageInput.value.trim()) {
                    onSendMessage(messageInput.value.trim())
                    messageInputActions.clear()
                } else if (!key.return) {
                    messageInputActions.handleKey(
                        key.backspace || key.delete ? 'backspace' :
                        key.leftArrow ? 'left' :
                        key.rightArrow ? 'right' :
                        input,
                        key.ctrl,
                        key.meta
                    )
                }
                break
        }
    })

    return (
        <Box flexDirection="column" width="100%" height="100%">
            {/* Header */}
            <Box
                borderStyle="single"
                borderColor="blue"
                paddingX={1}
                justifyContent="space-between"
            >
                <Text bold color="cyan">
                    Murmur - {account.firstName}
                    {account.lastName ? ` ${account.lastName}` : ''}
                </Text>
                <Text color="gray">
                    Tab: switch | Esc: back | Ctrl+N: add | Ctrl+P: profile | Ctrl+C: quit
                </Text>
            </Box>

            {/* Main content */}
            <TwoColumnLayout
                sidebarWidth={30}
                sidebar={
                    <BorderBox
                        title="Contacts"
                        height="100%"
                        focused={focusPanel === 'contacts'}
                    >
                        {contactItems.length === 0 ? (
                            <Box paddingX={1}>
                                <Text color="gray">
                                    No contacts yet.{'\n'}
                                    Press Ctrl+N to add one.
                                </Text>
                            </Box>
                        ) : (
                            <List
                                items={contactItems}
                                selectedIndex={selectedIndex}
                                scrollOffset={scrollOffset}
                                focused={focusPanel === 'contacts'}
                                maxVisible={15}
                            />
                        )}
                    </BorderBox>
                }
                main={
                    <Box flexDirection="column" height="100%">
                        {/* Messages panel */}
                        <BorderBox
                            title={selectedConversation
                                ? `${selectedConversation.contact.firstName}${
                                    selectedConversation.contact.lastName
                                        ? ` ${selectedConversation.contact.lastName}`
                                        : ''
                                }`
                                : 'Messages'
                            }
                            focused={focusPanel === 'messages'}
                        >
                            {selectedConversation ? (
                                <Box flexDirection="column" height="100%">
                                    <Box flexGrow={1}>
                                        <MessageList
                                            messages={messages}
                                            scrollOffset={messageScrollOffset}
                                            maxVisible={12}
                                        />
                                    </Box>
                                </Box>
                            ) : (
                                <Box
                                    justifyContent="center"
                                    alignItems="center"
                                    height="100%"
                                >
                                    <Text color="gray">
                                        Select a contact to view messages
                                    </Text>
                                </Box>
                            )}
                        </BorderBox>

                        {/* Input panel */}
                        {selectedConversation && (
                            <BorderBox
                                title="Message"
                                focused={focusPanel === 'input'}
                            >
                                <Box paddingX={1}>
                                    <TextInput
                                        value={messageInput.value}
                                        cursor={messageInput.cursor}
                                        placeholder="Type a message..."
                                        focused={focusPanel === 'input'}
                                    />
                                </Box>
                            </BorderBox>
                        )}
                    </Box>
                }
            />
        </Box>
    )
}
