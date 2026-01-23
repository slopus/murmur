/**
 * Tests for ProfileScreen component.
 */

import React from 'react'
import { describe, it, expect, vi } from 'vitest'
import { render } from 'ink-testing-library'
import { ProfileScreen } from './ProfileScreen.js'
import type { Account } from '../../storage/types.js'

describe('ProfileScreen', () => {
    const mockAccount: Account = {
        identityKey: 'test-identity-key-123456789abcdef',
        profilePublicKey: 'test-profile-public-key',
        profileSecretKey: 'test-profile-secret-key',
        encryptedProfile: 'test-encrypted-profile',
        firstName: 'Alice',
        lastName: 'Agent',
        createdAt: Date.now()
    }

    it('should render profile title', () => {
        const onNavigate = vi.fn()

        const { lastFrame } = render(
            <ProfileScreen account={mockAccount} onNavigate={onNavigate} />
        )
        const output = lastFrame()

        expect(output).toContain('Your Profile')
    })

    it('should show name', () => {
        const onNavigate = vi.fn()

        const { lastFrame } = render(
            <ProfileScreen account={mockAccount} onNavigate={onNavigate} />
        )
        const output = lastFrame()

        expect(output).toContain('Alice')
        expect(output).toContain('Agent')
    })

    it('should show identity key', () => {
        const onNavigate = vi.fn()

        const { lastFrame } = render(
            <ProfileScreen account={mockAccount} onNavigate={onNavigate} />
        )
        const output = lastFrame()

        expect(output).toContain('Identity Key')
        expect(output).toContain('test-identity-key-123456789abcdef')
    })

    it('should show sharing instructions', () => {
        const onNavigate = vi.fn()

        const { lastFrame } = render(
            <ProfileScreen account={mockAccount} onNavigate={onNavigate} />
        )
        const output = lastFrame()

        expect(output).toContain('share')
        expect(output).toContain('contact')
    })

    it('should show navigation instructions', () => {
        const onNavigate = vi.fn()

        const { lastFrame } = render(
            <ProfileScreen account={mockAccount} onNavigate={onNavigate} />
        )
        const output = lastFrame()

        expect(output).toContain('Enter')
        expect(output).toContain('Esc')
    })
})
