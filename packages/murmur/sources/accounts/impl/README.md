# Account implementation

`deviceRosterCodec.ts` owns canonical roster and MLS device-credential
encoding, signature checks, direct-child updates, and deterministic sibling
selection. `deviceProvisioning.ts` owns the ephemeral X25519 provisioning
transcript and authenticated encryption.

`accountRecords.ts` prepares only account-device lifecycle events and durable
roster convergence jobs.

```text
request proof -> intent check -> signed roster child -> encrypted response
      ^                                                    |
      `---------------- transcript hash -------------------'
```
