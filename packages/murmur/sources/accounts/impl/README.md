# Account implementation

`deviceRosterCodec.ts` owns strict current-roster and roster-mutation encoding.
The mutation is carried by an account-identity-signed ordinary delivery; the
relay authenticates it and atomically stores the resulting roster and inbox
notification.

`accountRecords.ts` prepares only account-device lifecycle events and durable
roster convergence jobs.

There is no provisioning transcript, roster chain, device credential, or
approval ceremony.
