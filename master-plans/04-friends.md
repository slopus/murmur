# Friends

## Destination

The next layer is not MLS. It is the first mechanism that lets people find and
add each other: a small protocol for sending a friend request, receiving it,
and sending a response.

Friend requests carry an encrypted profile and the related contact material.
Each person has exactly one public identity key associated somehow with a
public topic where requests can be written.

## One identity key

A Murmur identity exposes one public identity key, not separate public signing
and encryption keys. One underlying or root key identity must support both
signing and Diffie-Hellman or encryption through a deliberate conversion or
compatible construction. Systems such as Signal are an inspiration for this
direction.

## The exchange

1. A sender finds the public request topic associated with another person's
   public identity key and writes an encrypted friend request to it.
2. The recipient receives and reads the request, including the encrypted
   profile and contact material.
3. From the request, the recipient learns where to write the response and sends
   it there.

## Open question

The exact cryptographic construction is unresolved. We are not yet sure, and do
not currently remember, how the public identity key should be associated with
the public request topic or how the response address should be carried.

The Ed25519, X25519, or related construction that supports both signing and
Diffie-Hellman has also not been selected or verified here. Do not assume this
means ordinary reuse of the same raw key bytes for both operations, and do not
infer a specific construction from Signal. Do not choose these constructions as
part of this plan.

## How we know it is done

- Knowing a person's one public identity key is enough to send that person an
  encrypted friend request through a relay.
- The exchange exposes no separate public signing and encryption keys.
- The recipient can receive the request and recover its profile and contact
  material.
- The recipient can learn where to send the response, and the original sender
  can receive it.
- The exchange works without MLS.
