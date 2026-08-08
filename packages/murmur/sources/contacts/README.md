# Contacts

This module defines Murmur's built-in mutual contact handshake. Contact state is
anchored by a two-person technical MLS session; it is not a chat session and is
not an optional registered service.

```text
discovery digest
      |
      v
two-person contact session -- hello(profile) --> pending request
      |                                             |
      +<------------- hello(profile) -- accept -----+
      |
      v
durable confirmed contact
```

The session descriptor and packets are canonical, versioned JSON encrypted
inside MLS. A packet is either a profile `hello` or a contact `remove`.
Application profiles may contain bounded JSON data only. Codec functions return
defensive immutable values.

Durable record codecs live in `impl/`. They use a separate
`murmur/contacts/v1/` namespace so the v0.3.3 session record format remains
unchanged.
