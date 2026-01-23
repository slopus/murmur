/**
 * Input handling hook for text input fields.
 *
 * Manages cursor position, text editing, and keyboard navigation.
 */

import { useState, useCallback } from 'react'

export interface InputState {
    value: string
    cursor: number
}

export interface InputActions {
    setValue: (value: string) => void
    handleKey: (key: string, ctrl: boolean, meta: boolean) => void
    clear: () => void
}

/**
 * Text input state hook.
 */
export function useInput(initialValue: string = ''): [InputState, InputActions] {
    const [state, setState] = useState<InputState>({
        value: initialValue,
        cursor: initialValue.length
    })

    const setValue = useCallback((value: string) => {
        setState({ value, cursor: value.length })
    }, [])

    const clear = useCallback(() => {
        setState({ value: '', cursor: 0 })
    }, [])

    const handleKey = useCallback((key: string, ctrl: boolean, meta: boolean) => {
        setState(prev => {
            const { value, cursor } = prev

            // Ctrl+A - select all / go to start
            if (ctrl && key === 'a') {
                return { value, cursor: 0 }
            }

            // Ctrl+E - go to end
            if (ctrl && key === 'e') {
                return { value, cursor: value.length }
            }

            // Ctrl+U - clear line
            if (ctrl && key === 'u') {
                return { value: '', cursor: 0 }
            }

            // Ctrl+K - delete to end
            if (ctrl && key === 'k') {
                return { value: value.slice(0, cursor), cursor }
            }

            // Backspace
            if (key === 'backspace' || key === 'delete') {
                if (cursor > 0) {
                    const newValue = value.slice(0, cursor - 1) + value.slice(cursor)
                    return { value: newValue, cursor: cursor - 1 }
                }
                return prev
            }

            // Delete forward (Ctrl+D or actual delete key on some systems)
            if (ctrl && key === 'd') {
                if (cursor < value.length) {
                    const newValue = value.slice(0, cursor) + value.slice(cursor + 1)
                    return { value: newValue, cursor }
                }
                return prev
            }

            // Arrow left
            if (key === 'left') {
                return { value, cursor: Math.max(0, cursor - 1) }
            }

            // Arrow right
            if (key === 'right') {
                return { value, cursor: Math.min(value.length, cursor + 1) }
            }

            // Home
            if (key === 'home') {
                return { value, cursor: 0 }
            }

            // End
            if (key === 'end') {
                return { value, cursor: value.length }
            }

            // Regular character input
            if (key.length === 1 && !ctrl && !meta) {
                const newValue = value.slice(0, cursor) + key + value.slice(cursor)
                return { value: newValue, cursor: cursor + 1 }
            }

            return prev
        })
    }, [])

    return [state, { setValue, handleKey, clear }]
}
