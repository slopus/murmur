# Groups

## Destination

In Murmur, even two people may form a group. A normal one-to-one chat is a
two-member MLS group, and a group chat is the same primitive with more members.
Chat and group application interactions work through MLS.

The friend channel remains a separate pairwise bootstrap and control channel,
not a chat and not an MLS group. The sequence is: establish the friend channel,
send a private invitation and the material needed to start or join the group,
then begin the MLS group.

A group is fundamentally an MLS-protected ordered event stream. It uses a
`Read and Write Topic` derived from a secret known to the group. This plan does
not choose how that topic is derived or rotated.

Every group has an opaque descriptor that lets a client determine what the
group represents. This plan does not define the descriptor's contents.

## The group API

Creating a group means providing its descriptor. The public API then lets a
caller send opaque messages and add or remove people. These operations stay
primitive and simple.

Inviting or adding someone includes sending that person a special private
message through the friend channel, telling them that they were added and
carrying the material needed to start or join the group. This plan does not
define the exact welcome or payload.

## Unknown groups and synchronization

A client may ignore the application meaning of a group it does not understand.
It must still synchronize and retain that group's MLS state and events, so that
a later upgraded client can understand the group.

The public group API should not expose Murmur's synchronization choreography.
Whether synchronization happens in the background or through some explicit
mechanism remains an open question. This plan deliberately does not specify the
descriptor contents, application message contents, or exact synchronization
design.

## How we know it is done

- A normal one-to-one chat operates as a two-member MLS group, and the same
  primitive works for larger group chats.
- The non-MLS friend channel delivers the private invitation and material
  needed before the MLS group begins.
- A caller creates a group by supplying an opaque descriptor, then sends opaque
  messages and adds or removes people through a primitive public API.
- The group uses an MLS-protected ordered event stream on a shared
  `Read and Write Topic`.
- A person added to a group receives a private message telling them they were
  added.
- A client that does not understand a group's application meaning still keeps
  its MLS state and events synchronized for a later upgraded client.
- The public API does not expose synchronization choreography while the exact
  synchronization mechanism remains unresolved.
