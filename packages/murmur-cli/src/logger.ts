/**
 * Shared logger for CLI output diagnostics.
 */

import pino from 'pino'
import pinoPretty from 'pino-pretty'

const stream = pinoPretty({
    colorize: true,
    translateTime: 'SYS:standard',
    singleLine: true,
    ignore: 'pid,hostname',
    destination: 2
})

export const logger = pino(
    {
        level: process.env.MURMUR_LOG_LEVEL ?? 'info'
    },
    stream
)
