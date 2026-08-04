# Friend channel

## Destination

Once two people know each other, each has the other's public key and they share
a secret. This gives them an encrypted way to exchange both temporary and
durable interactions.

The simplest arrangement is for both sides to derive the same shared topic from
that secret. The shared secret is obtained using one's own secret key and the
other person's public key. This plan does not choose the exact derivation.

This is the relationship and control channel between two friends. It is not yet
the group layer.

## What the channel carries

Friends use the shared channel to:

- exchange profile updates;
- declare that the friendship has ended;
- announce or invite one another into a group;
- carry other later friend-to-friend protocol interactions.

## How we know it is done

- Two established friends derive the same shared topic from their existing key
  material and shared secret.
- They can exchange encrypted temporary and durable interactions over that
  topic.
- Profile updates, friendship termination, and group announcements or
  invitations can travel through the channel.
- The channel remains a friend relationship mechanism rather than the group
  layer itself.
