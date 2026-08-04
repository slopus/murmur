# Friends

## Destination

The next layer is not MLS. It is the first mechanism that lets people find and
add each other: a small protocol for sending a friend request, receiving it,
and sending a response.

Friend requests carry an encrypted profile and the related contact material.
Each person has a public key associated somehow with a public topic where
requests can be written.

## The exchange

1. A sender finds the public request topic associated with another person's
   public key and writes an encrypted friend request to it.
2. The recipient receives and reads the request, including the encrypted
   profile and contact material.
3. From the request, the recipient learns where to write the response and sends
   it there.

## Open question

The exact cryptographic construction is unresolved. We are not yet sure, and do
not currently remember, how the public key should be associated with the public
request topic or how the response address should be carried. Do not choose that
construction as part of this plan.

## How we know it is done

- Knowing a person's public key is enough to send that person an encrypted
  friend request through a relay.
- The recipient can receive the request and recover its profile and contact
  material.
- The recipient can learn where to send the response, and the original sender
  can receive it.
- The exchange works without MLS.
