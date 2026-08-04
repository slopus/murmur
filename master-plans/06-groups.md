# Groups

## Destination

In Murmur, a two-person interaction and a many-person interaction use the same
MLS group primitive. Murmur does not know whether the group represents a chat,
a document, or anything else; those semantics belong above the library.

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
caller send opaque events and add or remove people. These operations stay
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
The stateful library owns group synchronization, MLS epochs, and durable group
state through application-provided persistence. Exact scheduling is an
implementation choice. This plan deliberately does not specify the descriptor
contents, application event contents, or scheduling design.

## How we know it is done

- Two-person and many-person interactions use the same opaque descriptor-based
  MLS group stream primitive.
- The non-MLS friend channel delivers the private invitation and material
  needed before the MLS group begins.
- A caller creates a group by supplying an opaque descriptor, then sends opaque
  events and adds or removes people through a primitive public API.
- The group uses an MLS-protected ordered event stream on a shared
  `Read and Write Topic`.
- A person added to a group receives a private message telling them they were
  added.
- A client that does not understand a group's application meaning still keeps
  its MLS state and events synchronized for a later upgraded client.
- The stateful library owns synchronization and durable MLS group state without
  exposing choreography through the public group API.
