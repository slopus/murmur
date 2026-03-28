import { mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import type { MurmurP2pIdentity, StoredMessage } from './types.js'
import { createIdentity } from './identity.js'

interface PersistedState {
    identity: MurmurP2pIdentity | null
    messages: StoredMessage[]
}

const DEFAULT_STATE: PersistedState = {
    identity: null,
    messages: [],
}

/**
 * Small JSON-backed state store used by the daemon.
 */
export class StateStore {
    private readonly statePath: string
    private state: PersistedState | null = null
    private writeQueue: Promise<void> = Promise.resolve()

    constructor(private readonly dataDir: string) {
        this.statePath = join(dataDir, 'state.json')
    }

    /**
     * Ensure the data directory exists on disk.
     */
    async ensureReady(): Promise<void> {
        await mkdir(this.dataDir, { recursive: true })
    }

    /**
     * Load or create the daemon identity.
     */
    async loadOrCreateIdentity(name: string): Promise<MurmurP2pIdentity> {
        const state = await this.ensureLoaded()
        if (!state.identity) {
            state.identity = createIdentity(name)
            await this.persist(state)
            return state.identity
        }

        if (state.identity.name !== name) {
            state.identity = { ...state.identity, name }
            await this.persist(state)
        }

        return state.identity
    }

    /**
     * Return a snapshot of stored messages.
     */
    async listMessages(): Promise<StoredMessage[]> {
        const state = await this.ensureLoaded()
        return [...state.messages]
    }

    /**
     * Append a message and flush it to disk.
     */
    async appendMessage(message: StoredMessage): Promise<void> {
        const state = await this.ensureLoaded()
        state.messages.push(message)
        await this.persist(state)
    }

    private async ensureLoaded(): Promise<PersistedState> {
        if (this.state) {
            return this.state
        }

        await this.ensureReady()

        try {
            const raw = await readFile(this.statePath, 'utf8')
            this.state = JSON.parse(raw) as PersistedState
        } catch (error) {
            const code = (error as NodeJS.ErrnoException).code
            if (code !== 'ENOENT') {
                throw error
            }
            this.state = structuredClone(DEFAULT_STATE)
            await this.persist(this.state)
        }

        return this.state
    }

    private async persist(state: PersistedState): Promise<void> {
        const serialized = `${JSON.stringify(state, null, 2)}\n`
        const tempPath = `${this.statePath}.tmp`

        this.writeQueue = this.writeQueue.then(async () => {
            await writeFile(tempPath, serialized, 'utf8')
            await rename(tempPath, this.statePath)
        })

        await this.writeQueue
    }
}
