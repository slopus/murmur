# Directory

Pluggable authentication-ticket verification for exact identity-directory
claims. A verified ticket supplies a stable issuer, 32-byte ticket ID, expiry,
and shared claim budget. Ticket issuance, caller authentication, and directory
rate limiting remain outside the relay.

The directory only accepts exact account identity keys. It has no enumeration
or search operation, and known and unknown accounts use the same claim envelope.
