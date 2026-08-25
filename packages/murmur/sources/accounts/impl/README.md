# Account implementation

`deviceRosterCodec.ts` owns canonical roster and MLS device-credential
encoding, signature checks, direct-child updates, and deterministic sibling
selection. `deviceProvisioning.ts` owns the ephemeral X25519 provisioning
transcript and authenticated encryption.

```text
request proof -> intent check -> signed roster child -> encrypted response
      ^                                                    |
      `---------------- transcript hash -------------------'
```
