/**
 * Main Murmur application component.
 *
 * Renders the appropriate screen based on application state.
 */

import React from 'react'
import { Box, Text } from 'ink'
import { MurmurEngine } from '../engine/engine.js'
import { useApp } from './hooks/useApp.js'
import { SplashScreen } from './screens/SplashScreen.js'
import { SetupScreen } from './screens/SetupScreen.js'
import { ChatScreen } from './screens/ChatScreen.js'
import { AddContactScreen } from './screens/AddContactScreen.js'
import { ProfileScreen } from './screens/ProfileScreen.js'

export interface AppProps {
    engine: MurmurEngine
}

/**
 * Main application component.
 */
export function App({ engine }: AppProps) {
    const {
        state,
        createAccount,
        navigate,
        sendMessage,
        addContact,
        clearError
    } = useApp(engine)

    // Render appropriate screen
    let screen: React.ReactNode

    switch (state.screen.type) {
        case 'splash':
            screen = <SplashScreen />
            break

        case 'setup':
            screen = (
                <SetupScreen
                    step={state.screen.step}
                    error={state.screen.error}
                    onSubmit={createAccount}
                />
            )
            break

        case 'chat_list':
        case 'conversation':
            if (!state.account) {
                screen = <SplashScreen />
            } else {
                screen = (
                    <ChatScreen
                        account={state.account}
                        conversations={state.conversations}
                        selectedConversation={state.selectedConversation}
                        messages={state.messages}
                        onNavigate={navigate}
                        onSendMessage={sendMessage}
                    />
                )
            }
            break

        case 'add_contact':
            screen = (
                <AddContactScreen
                    onAddContact={addContact}
                    onNavigate={navigate}
                />
            )
            break

        case 'profile':
            if (!state.account) {
                screen = <SplashScreen />
            } else {
                screen = (
                    <ProfileScreen
                        account={state.account}
                        onNavigate={navigate}
                    />
                )
            }
            break

        default:
            screen = <SplashScreen />
    }

    return (
        <Box flexDirection="column" width="100%" height="100%">
            {screen}
        </Box>
    )
}
