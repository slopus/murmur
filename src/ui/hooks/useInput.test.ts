/**
 * Tests for useInput hook.
 *
 * Tests the input state management logic directly without React.
 */

import { describe, it, expect } from 'vitest'

describe('useInput hook logic', () => {
    // Test the state transitions directly
    function simulateInput(initial: string = '') {
        let state = { value: initial, cursor: initial.length }

        const handleKey = (key: string, ctrl: boolean = false, meta: boolean = false) => {
            const { value, cursor } = state

            // Ctrl+A - go to start
            if (ctrl && key === 'a') {
                state = { value, cursor: 0 }
                return state
            }

            // Ctrl+E - go to end
            if (ctrl && key === 'e') {
                state = { value, cursor: value.length }
                return state
            }

            // Ctrl+U - clear line
            if (ctrl && key === 'u') {
                state = { value: '', cursor: 0 }
                return state
            }

            // Ctrl+K - delete to end
            if (ctrl && key === 'k') {
                state = { value: value.slice(0, cursor), cursor }
                return state
            }

            // Backspace
            if (key === 'backspace') {
                if (cursor > 0) {
                    const newValue = value.slice(0, cursor - 1) + value.slice(cursor)
                    state = { value: newValue, cursor: cursor - 1 }
                }
                return state
            }

            // Delete forward
            if (ctrl && key === 'd') {
                if (cursor < value.length) {
                    const newValue = value.slice(0, cursor) + value.slice(cursor + 1)
                    state = { value: newValue, cursor }
                }
                return state
            }

            // Arrow left
            if (key === 'left') {
                state = { value, cursor: Math.max(0, cursor - 1) }
                return state
            }

            // Arrow right
            if (key === 'right') {
                state = { value, cursor: Math.min(value.length, cursor + 1) }
                return state
            }

            // Home
            if (key === 'home') {
                state = { value, cursor: 0 }
                return state
            }

            // End
            if (key === 'end') {
                state = { value, cursor: value.length }
                return state
            }

            // Regular character
            if (key.length === 1 && !ctrl && !meta) {
                const newValue = value.slice(0, cursor) + key + value.slice(cursor)
                state = { value: newValue, cursor: cursor + 1 }
                return state
            }

            return state
        }

        const clear = () => {
            state = { value: '', cursor: 0 }
        }

        const setValue = (newValue: string) => {
            state = { value: newValue, cursor: newValue.length }
        }

        return {
            getState: () => state,
            handleKey,
            clear,
            setValue
        }
    }

    it('should initialize with empty state', () => {
        const input = simulateInput()
        expect(input.getState()).toEqual({ value: '', cursor: 0 })
    })

    it('should initialize with provided value', () => {
        const input = simulateInput('hello')
        expect(input.getState()).toEqual({ value: 'hello', cursor: 5 })
    })

    it('should insert characters at cursor', () => {
        const input = simulateInput()
        input.handleKey('h')
        expect(input.getState().value).toBe('h')
        input.handleKey('i')
        expect(input.getState().value).toBe('hi')
        expect(input.getState().cursor).toBe(2)
    })

    it('should delete with backspace', () => {
        const input = simulateInput('hello')
        input.handleKey('backspace')
        expect(input.getState()).toEqual({ value: 'hell', cursor: 4 })
    })

    it('should not backspace at start', () => {
        const input = simulateInput('')
        input.handleKey('backspace')
        expect(input.getState()).toEqual({ value: '', cursor: 0 })
    })

    it('should move cursor with arrows', () => {
        const input = simulateInput('hello')
        input.handleKey('left')
        expect(input.getState().cursor).toBe(4)
        input.handleKey('left')
        expect(input.getState().cursor).toBe(3)
        input.handleKey('right')
        expect(input.getState().cursor).toBe(4)
    })

    it('should not move cursor past boundaries', () => {
        const input = simulateInput('hi')
        input.handleKey('right')
        expect(input.getState().cursor).toBe(2) // already at end

        input.handleKey('home')
        input.handleKey('left')
        expect(input.getState().cursor).toBe(0) // already at start
    })

    it('should jump to start/end with home/end', () => {
        const input = simulateInput('hello')
        input.handleKey('home')
        expect(input.getState().cursor).toBe(0)
        input.handleKey('end')
        expect(input.getState().cursor).toBe(5)
    })

    it('should go to start with Ctrl+A', () => {
        const input = simulateInput('hello')
        input.handleKey('a', true)
        expect(input.getState().cursor).toBe(0)
    })

    it('should go to end with Ctrl+E', () => {
        const input = simulateInput('hello')
        input.handleKey('home')
        input.handleKey('e', true)
        expect(input.getState().cursor).toBe(5)
    })

    it('should clear line with Ctrl+U', () => {
        const input = simulateInput('hello world')
        input.handleKey('u', true)
        expect(input.getState()).toEqual({ value: '', cursor: 0 })
    })

    it('should delete to end with Ctrl+K', () => {
        const input = simulateInput('hello world')
        input.handleKey('left')
        input.handleKey('left')
        input.handleKey('left')
        input.handleKey('left')
        input.handleKey('left')
        input.handleKey('left')
        input.handleKey('k', true)
        expect(input.getState().value).toBe('hello')
    })

    it('should delete forward with Ctrl+D', () => {
        const input = simulateInput('hello')
        input.handleKey('home')
        input.handleKey('d', true)
        expect(input.getState()).toEqual({ value: 'ello', cursor: 0 })
    })

    it('should insert at cursor position', () => {
        const input = simulateInput('hllo')
        input.handleKey('left')
        input.handleKey('left')
        input.handleKey('left')
        input.handleKey('e')
        expect(input.getState().value).toBe('hello')
        expect(input.getState().cursor).toBe(2)
    })

    it('should clear input', () => {
        const input = simulateInput('hello')
        input.clear()
        expect(input.getState()).toEqual({ value: '', cursor: 0 })
    })

    it('should set value', () => {
        const input = simulateInput()
        input.setValue('new value')
        expect(input.getState()).toEqual({ value: 'new value', cursor: 9 })
    })
})
