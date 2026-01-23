/**
 * Main application state hook.
 *
 * Manages the global application state including:
 * - Current screen (splash, chat list, conversation)
 * - Selected conversation
 * - Engine instance
 */

import { useState, useCallback, useEffect } from 'react'
import { MurmurEngine, type Conversation, type EngineEvent } from '../../engine/engine.js'
import type { Account, StoredMessage, Contact } from '../../storage/types.js'

/**
 * Application screen types.
 */
export type Screen =
    | { type: 'splash' }
    | { type: 'setup'; step: 'name' | 'creating' | 'error'; error?: string }
    | { type: 'chat_list' }
    | { type: 'conversation'; contactId: string }
    | { type: 'add_contact' }
    | { type: 'profile' }

/**
 * Application state.
 */
export interface AppState {
    screen: Screen
    account: Account | null
    conversations: Conversation[]
    selectedConversation: Conversation | null
    messages: StoredMessage[]
    isLoading: boolean
    error: string | null
}

/**
 * Application state hook.
 */
export function useApp(engine: MurmurEngine) {
    // Determine initial screen synchronously to avoid blink
    const initialScreen: Screen = engine.hasAccount()
        ? { type: 'splash' }
        : { type: 'setup', step: 'name' }

    const [state, setState] = useState<AppState>({
        screen: initialScreen,
        account: null,
        conversations: [],
        selectedConversation: null,
        messages: [],
        isLoading: engine.hasAccount(),
        error: null
    })

    /**
     * Initialize the application.
     */
    const initialize = useCallback(async () => {
        // If no account, we already set screen to setup in initial state
        if (!engine.hasAccount()) {
            return
        }

        try {
            const initialized = await engine.initialize()
            if (initialized) {
                const account = engine.getAccount()
                const conversations = engine.getConversations()
                setState(prev => ({
                    ...prev,
                    screen: { type: 'chat_list' },
                    account,
                    conversations,
                    isLoading: false
                }))
                engine.startSync()
            } else {
                // Account exists but initialization failed, show setup
                setState(prev => ({
                    ...prev,
                    screen: { type: 'setup', step: 'name' },
                    isLoading: false
                }))
            }
        } catch (error) {
            setState(prev => ({
                ...prev,
                screen: { type: 'setup', step: 'error', error: String(error) },
                isLoading: false,
                error: String(error)
            }))
        }
    }, [engine])

    /**
     * Create a new account.
     */
    const createAccount = useCallback(async (firstName: string, lastName?: string) => {
        setState(prev => ({
            ...prev,
            screen: { type: 'setup', step: 'creating' },
            isLoading: true
        }))

        try {
            const account = await engine.createAccount(firstName, lastName)
            const conversations = engine.getConversations()
            setState(prev => ({
                ...prev,
                screen: { type: 'chat_list' },
                account,
                conversations,
                isLoading: false
            }))
            engine.startSync()
        } catch (error) {
            setState(prev => ({
                ...prev,
                screen: { type: 'setup', step: 'error', error: String(error) },
                isLoading: false,
                error: String(error)
            }))
        }
    }, [engine])

    /**
     * Navigate to a screen.
     */
    const navigate = useCallback((screen: Screen) => {
        setState(prev => {
            const newState = { ...prev, screen }

            if (screen.type === 'conversation') {
                const conversation = prev.conversations.find(
                    c => c.contact.identityKey === screen.contactId
                )
                if (conversation) {
                    const messages = engine.getMessages(screen.contactId)
                    engine.markAsRead(screen.contactId)
                    return {
                        ...newState,
                        selectedConversation: conversation,
                        messages
                    }
                }
            }

            if (screen.type === 'chat_list') {
                return {
                    ...newState,
                    selectedConversation: null,
                    messages: [],
                    conversations: engine.getConversations()
                }
            }

            return newState
        })
    }, [engine])

    /**
     * Send a message.
     */
    const sendMessage = useCallback(async (text: string) => {
        if (!state.selectedConversation) return

        try {
            const message = await engine.sendMessage(
                state.selectedConversation.contact.identityKey,
                text
            )
            setState(prev => ({
                ...prev,
                messages: [...prev.messages, message]
            }))
        } catch (error) {
            setState(prev => ({
                ...prev,
                error: String(error)
            }))
        }
    }, [engine, state.selectedConversation])

    /**
     * Add a contact.
     */
    const addContact = useCallback(async (identityKey: string) => {
        try {
            await engine.addContact(identityKey)
            setState(prev => ({
                ...prev,
                screen: { type: 'chat_list' },
                conversations: engine.getConversations()
            }))
        } catch (error) {
            setState(prev => ({
                ...prev,
                error: String(error)
            }))
        }
    }, [engine])

    /**
     * Clear error.
     */
    const clearError = useCallback(() => {
        setState(prev => ({ ...prev, error: null }))
    }, [])

    /**
     * Handle engine events.
     */
    useEffect(() => {
        const unsubscribe = engine.on((event: EngineEvent) => {
            switch (event.type) {
                case 'message':
                    setState(prev => {
                        // If we're viewing this conversation, add the message
                        if (
                            prev.screen.type === 'conversation' &&
                            prev.screen.contactId === event.contact.identityKey
                        ) {
                            engine.markAsRead(event.contact.identityKey)
                            return {
                                ...prev,
                                messages: [...prev.messages, event.message]
                            }
                        }
                        // Otherwise just update conversations
                        return {
                            ...prev,
                            conversations: engine.getConversations()
                        }
                    })
                    break

                case 'contact_added':
                    setState(prev => ({
                        ...prev,
                        conversations: engine.getConversations()
                    }))
                    break

                case 'sync_complete':
                    setState(prev => ({
                        ...prev,
                        conversations: engine.getConversations()
                    }))
                    break

                case 'error':
                    setState(prev => ({
                        ...prev,
                        error: event.error
                    }))
                    break
            }
        })

        return unsubscribe
    }, [engine])

    /**
     * Initialize on mount.
     */
    useEffect(() => {
        initialize()
    }, [initialize])

    return {
        state,
        createAccount,
        navigate,
        sendMessage,
        addContact,
        clearError
    }
}
