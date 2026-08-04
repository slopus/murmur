# Friends

## Destination

The next layer is not MLS. It is the first mechanism that lets people find and
add each other: a small protocol for sending a friend request, receiving it,
and sending a response.

Friend requests carry an encrypted profile and the related contact material.
Each person has exactly one public identity key associated somehow with a
publicly addressable `Read Topic` where requests can be written.

## One identity key

A Murmur identity exposes one public identity key, not separate public signing
and encryption keys. Murmur will derive both Ed25519 signing and X25519
Diffie-Hellman or encryption capabilities from one underlying identity key
material and use that material for both. This does not claim that their
ordinary raw public-key encodings are identical; the exact conversion mechanics
remain unspecified.

There is no cryptographic proof or guarantee here that using the underlying
material for both capabilities is safe. We regard that concern as extremely
theoretical, intentionally accept the risk, and proceed with this decision.

## The exchange

1. A sender finds the request `Read Topic` associated with another person's
   public identity key and writes an encrypted friend request to it.
2. The recipient receives and reads the request, including the encrypted
   profile and contact material.
3. From the request, the recipient learns where to write the response and sends
   it there.

## Open question

We are not yet sure, and do not currently remember, how the public identity key
should be associated with the request `Read Topic` or how the response address
should be carried. The relay authorization model does not choose those
addressing mechanics.

## How we know it is done

- Knowing a person's one public identity key is enough to send that person an
  encrypted friend request through a relay.
- The exchange exposes no separate public signing and encryption keys.
- The recipient can receive the request and recover its profile and contact
  material.
- The recipient can learn where to send the response, and the original sender
  can receive it.
- The exchange works without MLS.
