# murmur-p2p

`murmur-p2p` is a separate package from the original Murmur client/server stack. It runs a local daemon, keeps a stable peer identity on disk, announces itself on the public HyperDHT, and sends encrypted peer-to-peer messages over hole-punched connections.

## Why this package exists

- No central Murmur server
- Local Unix control socket for CLI-to-daemon communication
- Stable peer identity backed by a persisted HyperDHT keypair
- Public DHT presence so peers can discover each other in a torrent-like way
- Lightweight direct-message framing instead of a full messaging protocol stack

## Commands

```bash
yarn dev server --name alice
yarn dev server --name alice --transport-debug
yarn dev whoami
yarn dev peers
yarn dev send --to <peer-id> --message "hello"
yarn dev messages
```

The daemon stores state in `~/.murmur-p2p` by default and exposes `~/.murmur-p2p/control.sock`.

## Design

Each daemon does four things:

1. Creates or loads a stable HyperDHT keypair.
2. Listens for encrypted P2P connections on that public key.
3. Announces itself on a shared application topic in the DHT.
4. Accepts local control commands over a Unix socket and dials peers on demand.

Messages are newline-delimited JSON frames over the encrypted HyperDHT socket. The control socket is also newline-delimited JSON to keep the CLI and daemon loosely coupled.

## Prior art

This package is intentionally lighter than full libp2p or a full Signal-style ratchet. The main references that shaped it:

- HyperDHT / Hyperswarm: <https://github.com/holepunchto/hyperdht>
- HyperDHT docs: <https://docs.pears.com/building-blocks/hyperdht>
- libp2p NAT traversal and relay docs: <https://docs.libp2p.io/>
- Kademlia paper: <https://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf>
- UDP hole punching background: <https://brynosaurus.com/pub/net/p2pnat/>

## Testing

```bash
yarn typecheck
yarn test
yarn build
yarn demo:live
```

`yarn demo:live` starts two temporary daemons on the public HyperDHT, waits for discovery, sends a message through the local control socket, and verifies delivery.

`yarn demo:live-debug` runs the same flow with low-level transport logging: announced relay nodes, connect latency, final UDX endpoint, local socket endpoint, RTT, and an inferred `direct` vs `relay-assisted` mode.
