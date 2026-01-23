/**
 * Spinner component for loading states.
 */

import React, { useState, useEffect } from 'react'
import { Text } from 'ink'

const SPINNER_FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']

export interface SpinnerProps {
    label?: string
}

/**
 * Animated spinner component.
 */
export function Spinner({ label }: SpinnerProps) {
    const [frameIndex, setFrameIndex] = useState(0)

    useEffect(() => {
        const timer = setInterval(() => {
            setFrameIndex(prev => (prev + 1) % SPINNER_FRAMES.length)
        }, 80)

        return () => clearInterval(timer)
    }, [])

    return (
        <Text color="cyan">
            {SPINNER_FRAMES[frameIndex]}
            {label && ` ${label}`}
        </Text>
    )
}
