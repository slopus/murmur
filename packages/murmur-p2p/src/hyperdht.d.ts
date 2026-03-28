declare module 'hyperdht' {
    import { EventEmitter } from 'node:events'
    import { Duplex } from 'node:stream'

    export interface KeyPair {
        publicKey: Buffer
        secretKey: Buffer
    }

    export interface RelayAddress {
        host: string
        port: number
    }

    export interface LookupPeer {
        publicKey: Buffer
        nodes: RelayAddress[]
    }

    export interface LookupResult {
        peers: LookupPeer[]
    }

    export interface QueryStream<T> extends AsyncIterable<T> {
        finished(): Promise<void>
    }

    export interface ConnectOptions {
        nodes?: RelayAddress[]
        keyPair?: KeyPair
    }

    export interface ServerOptions {
        firewall?: (remotePublicKey: Buffer, remoteHandshakePayload?: unknown) => boolean
        holepunch?: boolean | (() => boolean)
    }

    export interface HyperDHTOptions {
        bootstrap?: Array<string | RelayAddress>
        keyPair?: KeyPair
    }

    export interface DhtSocket extends Duplex {
        remotePublicKey: Buffer
        publicKey: Buffer
    }

    export class DhtServer extends EventEmitter {
        publicKey: Buffer | null
        relayAddresses: RelayAddress[]
        listen(keyPair: KeyPair): Promise<this>
        close(): Promise<void>
        address(): { publicKey: Buffer; host: string; port: number } | null
        on(event: 'connection', listener: (socket: DhtSocket) => void): this
    }

    export default class HyperDHT extends EventEmitter {
        constructor(options?: HyperDHTOptions)
        static keyPair(seed?: Uint8Array): KeyPair
        static bootstrapper(port?: number, host?: string): HyperDHT
        createServer(options?: ServerOptions, onconnection?: (socket: DhtSocket) => void): DhtServer
        connect(remotePublicKey: string | Uint8Array, options?: ConnectOptions): DhtSocket
        destroy(options?: { force?: boolean }): Promise<void>
        lookup(topic: Uint8Array): QueryStream<LookupResult>
        announce(topic: Uint8Array, keyPair: KeyPair, relayAddresses?: RelayAddress[]): QueryStream<LookupResult>
    }
}

declare module 'hyperdht/testnet.js' {
    import HyperDHT, { RelayAddress } from 'hyperdht'

    export interface HyperDhtTestnet {
        bootstrap: RelayAddress[]
        createNode(options?: object): HyperDHT
        destroy(): Promise<void>
    }

    export default function createTestnet(size?: number, options?: object): Promise<HyperDhtTestnet>
}
