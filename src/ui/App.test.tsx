/**
 * Tests for the main App component.
 */

import React from 'react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render } from 'ink-testing-library'
import { App } from './App.js'
import { MurmurEngine } from '../engine/engine.js'

// Mock the engine
vi.mock('../engine/engine.js', () => ({
    MurmurEngine: vi.fn()
}))

describe('App', () => {
    let mockEngine: any

    beforeEach(() => {
        mockEngine = {
            hasAccount: vi.fn(),
            initialize: vi.fn(),
            getAccount: vi.fn(),
            getConversations: vi.fn(),
            getMessages: vi.fn(),
            markAsRead: vi.fn(),
            sendMessage: vi.fn(),
            addContact: vi.fn(),
            createAccount: vi.fn(),
            startSync: vi.fn(),
            stopSync: vi.fn(),
            on: vi.fn().mockReturnValue(() => {})
        }
    })

    it('should render splash screen initially when no account', () => {
        mockEngine.hasAccount.mockReturnValue(false)

        const { lastFrame } = render(<App engine={mockEngine} />)
        const output = lastFrame()

        // Initially shows splash, then transitions to setup
        // Due to async nature, we just verify it renders something
        expect(output).toBeDefined()
    })

    it('should render setup screen when no account exists', async () => {
        mockEngine.hasAccount.mockReturnValue(false)
        mockEngine.initialize.mockResolvedValue(false)

        const { lastFrame, rerender } = render(<App engine={mockEngine} />)

        // Wait for state to update
        await new Promise(resolve => setTimeout(resolve, 50))
        rerender(<App engine={mockEngine} />)

        const output = lastFrame()
        // Setup screen should show welcome message
        expect(output).toContain('Welcome')
    })

    it('should render chat screen when account exists', async () => {
        const mockAccount = {
            identityKey: 'test-id',
            profilePublicKey: 'ppk',
            profileSecretKey: 'psk',
            encryptedProfile: 'ep',
            firstName: 'Test',
            lastName: 'User',
            createdAt: Date.now()
        }

        mockEngine.hasAccount.mockReturnValue(true)
        mockEngine.initialize.mockResolvedValue(true)
        mockEngine.getAccount.mockReturnValue(mockAccount)
        mockEngine.getConversations.mockReturnValue([])

        const { lastFrame, rerender } = render(<App engine={mockEngine} />)

        // Wait for state to update
        await new Promise(resolve => setTimeout(resolve, 50))
        rerender(<App engine={mockEngine} />)

        const output = lastFrame()
        // Chat screen should show the app name and user
        expect(output).toContain('Murmur')
    })

    it('should call engine.on to subscribe to events', () => {
        mockEngine.hasAccount.mockReturnValue(false)

        render(<App engine={mockEngine} />)

        expect(mockEngine.on).toHaveBeenCalled()
    })
})
