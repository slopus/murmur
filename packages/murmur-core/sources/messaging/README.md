# Messaging

Application content carried inside an encrypted group application message.
Pairwise chat uses the same content type as any other two-member group.

Files are always encrypted before upload. The descriptor contains the secret
file key and therefore must only appear inside encrypted application data.

```text
plaintext file -> AES-256-GCM -> relay blob
       key + metadata --------> encrypted message descriptor
```
