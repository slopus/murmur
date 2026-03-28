import DHT from 'hyperdht'
import type { MurmurP2pIdentity } from './types.js'
import { createSeed, fromHex, toHex } from './utils.js'

/**
 * Create a brand-new persistent daemon identity.
 */
export function createIdentity(name: string): MurmurP2pIdentity {
    const seed = createSeed()
    const keyPair = DHT.keyPair(seed)

    return {
        seedHex: toHex(seed),
        peerId: toHex(keyPair.publicKey),
        name,
        createdAt: new Date().toISOString(),
    }
}

/**
 * Rebuild the HyperDHT keypair from persisted identity state.
 */
export function keyPairFromIdentity(identity: MurmurP2pIdentity): {
    publicKey: Buffer
    secretKey: Buffer
} {
    return DHT.keyPair(fromHex(identity.seedHex))
}
